<?php

declare(strict_types=1);

/*
 * Runs the identifier-equality upgrade over a seeded table in a FRESH process,
 * under whatever memory limit the caller sets.
 *
 * #61. The scan read every row of every identifier table into PHP before
 * deciding anything, at a measured 857 bytes per row, so a large installation
 * could not complete the upgrade at all. That is only observable as memory
 * exhaustion, and a test that observes it by dying needs a limit of its own --
 * asserting it inline would make the whole suite's `memory_limit` load-bearing
 * for one test, which is the trap the wide-policy guard documents next door.
 *
 * Framework-free on purpose: a standalone PDO connection, and the three tables
 * created here with only the columns the upgrade reads. Booting Testbench would
 * put 30 MB of baseline between the limit and the thing being measured, and the
 * upgrade's behaviour against the real schema is covered by the migration tests
 * that run on all three engines. What this fixture measures is the SHAPE of the
 * scan's memory, which does not depend on the columns it ignores.
 *
 * Two SHAPES, because they measure different properties and only one of them used
 * to be measured here.
 *
 * `canonical` seeds values the upgrade leaves alone, which isolates the cost of
 * the scan itself -- #61's defect, where every row was read into PHP before
 * anything was decided.
 *
 * `uppercase` seeds values every one of which must be REWRITTEN, which is
 * #92. This file used to record the resulting growth as being "by design",
 * since the rewrite deduplicates by spelling to keep itself to a statement per
 * chunk. That reasoning is sound and the conclusion was still wrong: when every
 * spelling is distinct, one pair per spelling is one pair per row, and a host
 * whose identifiers are not yet canonical is exactly the host this migration
 * exists for. Measured against the accumulating rewrite: 100 000 rows peaked at
 * 45 MiB against a 6 MiB baseline and 400 000 exhausted a 128 MB limit.
 *
 * Both shapes seed HASH-DERIVED values, which is load-bearing rather than
 * decoration. With predictable `user-N@...` values, an implementation that
 * retained every pair in a compressed stream quadrupled its retained bytes
 * between 100 000 and 400 000 rows while reporting the same 8 MiB peak, and
 * passed a growth comparison with zero slack -- compression, not bounding, is
 * what kept it inside. A hash-derived local part carries enough entropy to
 * expose that accumulator at these sizes, which is the claim the evidence
 * supports: hex encoding and a shared domain still compress somewhat, so this
 * is not "incompressible", only compressible far less than `user-N@`.
 * Deterministic, so a failure is reproducible.
 *
 * The expectations are seeded into a table of their own rather than recomputed
 * at the end, because the point of a hash-derived value is that no SQL
 * expression can derive it. The join at the end is bounded; holding 400 000
 * expected values in PHP would not be.
 *
 * Prints four numbers: surviving rows, rows whose value matches the expectation seeded
 * for their own subject, peak allocation, and the milliseconds apply() took. The last is
 * for #101 -- memory being flat says nothing about the time, and the two have to be
 * measured separately because fixing one has cost the other before.
 *
 * Usage: php -d memory_limit=16M identifier-upgrade-scan.php <package-root> <rows> [shape]
 *        shape: canonical (default) | uppercase | control
 */

require $argv[1] . '/vendor/autoload.php';

use Fissible\Vouch\Identifiers\IdentifierEqualityUpgrade;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\SQLiteConnection;

$rows = (int) $argv[2];

/*
 * The control. Proves the limit this process was given is actually enforced:
 * without it, a guard asserting "the upgrade completed under 16M" would pass
 * just as happily in a process whose limit was never applied.
 */
$shape = $argv[3] ?? 'canonical';

if ($shape === 'control') {
    $ballast = str_repeat('x', 64 * 1024 * 1024);
    echo strlen($ballast), PHP_EOL;

    exit(0);
}

$path = tempnam(sys_get_temp_dir(), 'vouch-upgrade-scan-') . '.sqlite';
touch($path);

$connection = new SQLiteConnection(
    new PDO('sqlite:' . $path, null, null, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]),
    // The file, not 'main': the constructor's $database and the config's must not
    // give two answers to one question.
    $path,
    '',
    ['driver' => 'sqlite', 'database' => $path],
);

try {
    $connection->statement(
        'create table auth_identifiers (id integer primary key autoincrement, '
        . 'user_id integer not null, type varchar(32) not null, value varchar(255) not null, '
        /*
         * The real unique index, and it is not decoration. The loose-class read is a
         * correlated subquery, so without it SQLite full-scans the table once per
         * row: measured on the same fixture and the same correct implementation,
         * 10000 rows took 3.75s without it and 0.26s with -- fourteen times -- and
         * 100000 rows are 1.37s with it. The schema is also simply honest this way,
         * since that index is what the scan's own docblock says it relies on.
         */
        . 'unique (type, value))',
    );
    $connection->statement(
        'create table auth_identifier_verifications (id integer primary key autoincrement, '
        . 'identifier_type varchar(32) not null, identifier_value varchar(255) not null, '
        . 'consumed_at datetime null, burned_at datetime null)',
    );
    $connection->statement(
        'create table auth_recovery_proofs (id integer primary key autoincrement, '
        . 'identifier_type varchar(32) not null, identifier_value varchar(255) not null, '
        . 'consumed_at datetime null, burned_at datetime null)',
    );
    /*
     * Not one of the upgrade's tables, so it reads and writes nothing here. It records
     * what each subject's identifier must become, so the check at the end can be a
     * join rather than a predicate over values no SQL function can derive.
     */
    $connection->statement(
        'create table upgrade_expected (user_id integer not null primary key, '
        . 'type varchar(32) not null, value varchar(255) not null)',
    );

    $connection->beginTransaction();

    for ($start = 0; $start < $rows; $start += 500) {
        $tuples = [];
        $bindings = [];
        $expectedTuples = [];
        $expectedBindings = [];

        for ($i = $start; $i < min($start + 500, $rows); $i++) {
            /*
             * Distinct per row in BOTH shapes, so the row count and the distinct
             * spelling count are the same number and no measurement here can be
             * satisfied by accidental deduplication -- and incompressible, so
             * retained pairs cannot hide inside a constant peak.
             */
            $local = substr(sha1((string) $i), 0, 20);
            $canonical = $local . '@acme.example';

            /*
             * THREE types, cycled per row, so every page of the scan and of the rewrite
             * contains more than one -- and two of them are themselves non-canonical, so
             * the type column needs rewriting as well as the value column.
             *
             * Measured against a single-type fixture: a rewrite that qualified every
             * value update by the FIRST ROW's type passed the whole file on all three
             * engines, and rewrote 300 of 300 email rows and 0 of 300 username rows.
             * One type cannot catch that, whatever else the fixture varies.
             */
            $types = ['email', 'EMAIL', 'Username'];
            $type = $types[$i % count($types)];
            $canonicalType = strtolower($type);

            $tuples[] = '(?, ?, ?)';
            $bindings[] = $i + 1;
            $bindings[] = $type;
            $bindings[] = $shape === 'uppercase'
                ? strtoupper($local) . '@ACME.EXAMPLE'
                : $canonical;

            $expectedTuples[] = '(?, ?, ?)';
            $expectedBindings[] = $i + 1;
            $expectedBindings[] = $canonicalType;
            $expectedBindings[] = $canonical;
        }

        $connection->insert(
            'insert into auth_identifiers (user_id, type, value) values ' . implode(', ', $tuples),
            $bindings,
        );
        $connection->insert(
            'insert into upgrade_expected (user_id, type, value) values ' . implode(', ', $expectedTuples),
            $expectedBindings,
        );
    }

    $connection->commit();

    $started = microtime(true);

    (new IdentifierEqualityUpgrade($connection, new IdentifierCanonicalizer()))->apply();

    $finished = microtime(true);

    /*
     * The surviving row count rather than a bare "ok": an upgrade that answered by
     * deleting the table, or that refused and left the rows alone having done no
     * work, prints a different number rather than the same success.
     */
    /*
     * The second number is each row's OWN expected value, derived from the identity it
     * was seeded with, not merely a canonical-looking one.
     *
     * Measured against a mutant that kept each batch's first target and rotated the
     * rest: every row came out lower-case and 99 500 of 100 000 belonged to the wrong
     * owner, and a count of canonical-looking rows passed it. An identifier moved to
     * another subject is worse than one left un-canonicalized, so the predicate has to
     * tie the value back to user_id.
     *
     * SQLite's `||`, because this fixture is deliberately SQLite-only and
     * framework-free; the cross-engine equivalent lives in the migration tests, which
     * compare in PHP over a table small enough to hold.
     */
    /*
     * All THREE columns, because a rewrite can get the value right for the wrong type: a
     * mutant qualifying by the first row's type left two of three types untouched while
     * every value it did rewrite was correct.
     */
    $expected = (int) $connection->table('auth_identifiers')
        ->join('upgrade_expected', function ($join): void {
            $join->on('upgrade_expected.user_id', '=', 'auth_identifiers.user_id')
                ->on('upgrade_expected.type', '=', 'auth_identifiers.type')
                ->on('upgrade_expected.value', '=', 'auth_identifiers.value');
        })
        ->count();

    /*
     * And the PEAK, so a caller can compare two row counts instead of only asking
     * whether each fitted. "Completes under 16M" is satisfied by any implementation
     * whose constant is small enough for the sizes tested -- measured, pairs held as
     * length-prefixed COMPRESSED batches retained 0.765 MiB at 100 000 rows and
     * 3.128 MiB at 400 000 and passed both, dying only at 1.6M. Growth is the
     * property; a limit is only ever a proxy for it.
     *
     * Real allocation rather than the emalloc figure: the limit is applied to the
     * former, and it is the one that makes a run fail.
     */
    /*
     * And the ELAPSED time of apply() alone, excluding the seeding above, so a caller can
     * compare two row counts. #92 bounded memory and left the time super-linear: the
     * rewrite matched rows by spelling, which the unique index on (type, value) cannot
     * serve from the value alone, so every chunk full-scanned the table. Measured before
     * #101: 24 s at 100 000 rows and 247 s at 400 000 -- four times the rows, ten times
     * the time.
     */
    echo (int) $connection->table('auth_identifiers')->count(), ' ', $expected,
        ' ', memory_get_peak_usage(true), ' ', (int) round(($finished - $started) * 1000), PHP_EOL;
} finally {
    @unlink($path);
}
