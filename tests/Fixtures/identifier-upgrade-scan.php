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
 * The rows are seeded already canonical. The rewrite deduplicates by spelling,
 * so rows that all need rewriting cost memory proportional to distinct spellings
 * by design, and that is a different property from the one under test.
 *
 * Usage: php -d memory_limit=16M identifier-upgrade-scan.php <package-root> <rows> [control]
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
if (($argv[3] ?? '') === 'control') {
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

    $connection->beginTransaction();

    for ($start = 0; $start < $rows; $start += 500) {
        $tuples = [];
        $bindings = [];

        for ($i = $start; $i < min($start + 500, $rows); $i++) {
            $tuples[] = '(?, ?, ?)';
            $bindings[] = $i + 1;
            $bindings[] = 'email';
            $bindings[] = sprintf('user-%d@acme.example', $i);
        }

        $connection->insert(
            'insert into auth_identifiers (user_id, type, value) values ' . implode(', ', $tuples),
            $bindings,
        );
    }

    $connection->commit();

    (new IdentifierEqualityUpgrade($connection, new IdentifierCanonicalizer()))->apply();

    /*
     * The surviving row count rather than a bare "ok": an upgrade that answered by
     * deleting the table, or that refused and left the rows alone having done no
     * work, prints a different number rather than the same success.
     */
    echo (int) $connection->table('auth_identifiers')->count(), PHP_EOL;
} finally {
    @unlink($path);
}
