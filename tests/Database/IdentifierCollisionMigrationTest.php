<?php

declare(strict_types=1);

use Fissible\Vouch\Identifiers\IdentifierCollisionsFound;
use Fissible\Vouch\Identifiers\IdentifierEqualityUpgrade;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\QueryException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Config;

uses(DatabaseMigrations::class);

/*
 * #59, the upgrade half. What happens to installations whose rows disagree with
 * the new definition of identity.
 *
 * Settling equality moves rows in two directions, and only one of them is
 * obvious.
 *
 * MERGES. Two rows that differ in bytes canonicalize to one value. This is the
 * likely case in practice, because mixed-case duplicates accumulate quietly on
 * the engines that keep them apart, and the unique constraint DOES break: the
 * migration cannot write both.
 *
 * SPLITS. Two rows an accent-insensitive collation treated as one become two.
 * Nothing breaks structurally, but proofs that were one account's are now
 * divided. NOTE these are constructible only in the proof and verification
 * tables: auth_identifiers carries unique(type, value), and under ai_ci that
 * index REJECTS the second insert -- measured, SQLSTATE 23000. An earlier
 * version of this file built the pair there and claimed ai-equality was what
 * let it in; the opposite is true, and the test could never have passed.
 *
 * WHAT THE MIGRATION DOES. auth_identifiers always refuses, because that row is
 * the account and Vouch cannot know which of two addresses owns it. The proof
 * and verification tables hold minute-scale credentials, so colliding rows
 * there are DELETED when they are still live -- costing a user a re-request --
 * and refused when consumed or burned, because those are the record that
 * something happened and #31 and #38 both treat terminal states as permanent.
 *
 * WHY EVERY TEST REVERTS THE COLLATION FIRST. DatabaseMigrations has already run
 * the migration under test, so a test body that simply calls it again measures
 * an idempotent re-run against an already-converted schema -- which is not the
 * upgrade path, and is the only reason the migration exists. Reverting first is
 * what makes these tests about the thing they name.
 */

/**
 * Every column the migration converts.
 *
 * @return list<array{string, string}>
 */
function convertedColumns(): array
{
    /*
     * Delegated rather than duplicated. This list and identifierColumns() were
     * byte-identical copies in two files, so adding a ninth identifier column
     * meant changing both or having one silently stop covering it.
     */
    return identifierColumns();
}

/**
 * Put the schema back the way an unmigrated installation has it.
 *
 * SQLite has no collation to revert -- text compares as bytes already -- so
 * there the upgrade is the row rewrite alone, and the DDL assertions skip.
 *
 * $except exists for a specific and non-obvious reason. auth_identifiers
 * carries unique(type, value), and under an accent-insensitive collation that
 * index rejects a MERGE fixture as surely as it rejects a split one: Ada@ and
 * ada@ are ai-equal, so the second insert fails with SQLSTATE 23000. A merge in
 * that table is constructible only under a deterministic collation -- natively
 * on SQLite and PostgreSQL, and after conversion on MySQL.
 *
 * Leaving it converted is not a weakening. The collation change for that column
 * is asserted by its own test; these tests are about whether the migration
 * DETECTS the merge, and that is what stays under test.
 *
 * @param list<string> $except tables to leave as they are
 */
function revertToLegacyCollation(array $except = []): void
{
    $driver = DB::connection()->getDriverName();

    if ($driver === 'sqlite') {
        return;
    }

    foreach (convertedColumns() as [$table, $column]) {
        if (in_array($table, $except, true)) {
            continue;
        }

        $driver === 'mysql'
            ? DB::statement(sprintf(
                'alter table %s modify %s varchar(255) character set utf8mb4 '
                . 'collate utf8mb4_0900_ai_ci not null',
                $table,
                $column,
            ))
            : DB::statement(sprintf(
                'alter table %s alter column %s type varchar(255) collate pg_catalog."default"',
                $table,
                $column,
            ));
    }
}

function runIdentifierMigration(): void
{
    $migration = require dirname(__DIR__, 2)
        . '/database/migrations/2026_09_25_000001_deterministic_identifier_equality.php';

    if (! is_object($migration)) {
        throw new RuntimeException('The identifier migration file returned no object.');
    }

    $up = [$migration, 'up'];

    if (! is_callable($up)) {
        throw new RuntimeException('The identifier migration has no callable up().');
    }

    $up();
}

/** Insert an identifier row bypassing any application-side canonicalization. */
function rawIdentifier(string $value, int $userId, string $type = 'email'): int
{
    return (int) DB::table('auth_identifiers')->insertGetId([
        'user_id' => $userId,
        'type' => $type,
        'value' => $value,
        'verified_at' => now(),
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}

/** Insert a recovery proof row directly, in whatever spelling is asked for. */
function rawProof(string $value, ?string $consumedAt = null, ?string $burnedAt = null): int
{
    return (int) DB::table('auth_recovery_proofs')->insertGetId([
        'identifier_type' => 'email',
        'identifier_value' => $value,
        'code_hash' => 'hash-' . bin2hex(random_bytes(4)),
        'is_decoy' => false,
        'attempts' => 0,
        'expires_at' => now()->addMinutes(5),
        'consumed_at' => $consumedAt,
        'burned_at' => $burnedAt,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}

/**
 * Every table name in the database this connection is pointed at.
 *
 * Scoped to the current schema on purpose: an unscoped listing on MySQL
 * enumerates every schema on the server, so a scratch table from an unrelated
 * checkout would read as residue from this run.
 *
 * @return list<string>
 */
function tableNames(): array
{
    $driver = DB::connection()->getDriverName();

    /*
     * Aliased to one name in every branch, because the engines disagree about the
     * spelling they hand back: MySQL 8 returns TABLE_NAME in upper case from
     * information_schema, so reading `->table_name` is an undefined property there
     * while SQLite happens to work. An explicit alias is the only spelling all
     * three agree on.
     */
    $rows = match ($driver) {
        'sqlite' => DB::select("select name as listed from sqlite_master where type = 'table'"),
        'mysql' => DB::select('select table_name as listed from information_schema.tables where table_schema = database()'),
        default => DB::select('select tablename as listed from pg_tables where schemaname = current_schema()'),
    };

    $names = [];

    foreach ($rows as $row) {
        $names[] = stringValue(requiredRow($row)->listed);
    }

    sort($names);

    return $names;
}

/**
 * Every table the package itself declares, plus the ones the harness owns.
 *
 * An ABSOLUTE expectation rather than a before-and-after diff, because a diff
 * cannot see this. DatabaseMigrations runs the migration under test in setUp,
 * before any test body, so a working table the scan failed to drop is already
 * present when a baseline is captured and the difference is empty by
 * construction -- measured: an implementation that never drops its working table
 * on the refusal path was green on the whole file, in sequence and in isolation,
 * with the table still in information_schema afterwards.
 *
 * Derived from the migrations rather than listed here so that adding a table does
 * not silently weaken it: a new Schema::create() extends this set on its own, and
 * a table created by anything else fails here and has to be accounted for.
 *
 * Scope note: permanent objects only. A TEMPORARY working table is absent from
 * sqlite_master, from information_schema.tables and from pg_tables alike, because
 * it dies with the connection -- which is a legitimate way to leave no residue
 * rather than a hole in this guard.
 *
 * @return list<string>
 */
function expectedTableNames(): array
{
    /*
     * The harness's own table, plus the one the migrations create from a CLASS
     * CONSTANT rather than a literal. The first version of this helper matched only
     * quoted names and so failed against a perfectly clean database, naming the
     * table it had not accounted for -- which is the right failure, and the reason
     * this is a short explicit list rather than a cleverer regex: a future
     * constant-named table fails here by name and gets accounted for deliberately.
     */
    $names = [
        'migrations',
        // Sanctum's, loaded by the provider when the package is installed rather than
        // declared by any migration here.
        'personal_access_tokens',
        \Fissible\Vouch\Support\IssuanceLockBucket::TABLE,
    ];

    if (DB::connection()->getDriverName() === 'sqlite') {
        $names[] = 'sqlite_sequence';
    }

    foreach (glob(dirname(__DIR__, 2) . '/database/migrations/*.php') ?: [] as $file) {
        $source = file_get_contents($file);

        if (! is_string($source)) {
            throw new RuntimeException('A migration file is unreadable: ' . $file);
        }

        if (preg_match_all("/Schema::create\('([a-z_]+)'/", $source, $matches) === false) {
            continue;
        }

        foreach ($matches[1] as $name) {
            $names[] = $name;
        }
    }

    $names = array_values(array_unique($names));
    sort($names);

    return $names;
}

/** Whether an index still exists, asked of the engine. */
function indexExists(string $table, string $index): bool
{
    $driver = DB::connection()->getDriverName();

    if ($driver === 'sqlite') {
        return DB::table('sqlite_master')->where('type', 'index')->where('name', $index)->exists();
    }

    if ($driver === 'mysql') {
        return DB::selectOne(
            'select 1 as present from information_schema.statistics '
            . 'where table_schema = database() and table_name = ? and index_name = ? limit 1',
            [$table, $index],
        ) !== null;
    }

    return DB::selectOne('select 1 as present from pg_indexes where indexname = ? limit 1', [$index]) !== null;
}

it('upgrades an installation whose identifiers already agree', function (): void {
    revertToLegacyCollation();
    rawIdentifier('ada@acme.example', 1);
    rawIdentifier('grace@acme.example', 2);

    /*
     * The clean path, asserted first so a migration that refused everything
     * cannot pass the refusal tests below by being uniformly broken.
     */
    runIdentifierMigration();

    expect(DB::table('auth_identifiers')->orderBy('value')->pluck('value')->all())
        ->toBe(['ada@acme.example', 'grace@acme.example']);
});

it('is safe to run twice', function (): void {
    revertToLegacyCollation();
    rawIdentifier('ada@acme.example', 1);

    // The harness runs it once before the test body regardless, so a migration
    // whose DDL is not idempotent would be rejected by every test here.
    runIdentifierMigration();
    runIdentifierMigration();

    expect(DB::table('auth_identifiers')->count())->toBe(1);
});

it('canonicalizes rows that are unambiguous', function (): void {
    revertToLegacyCollation();
    $id = rawIdentifier("JOS\u{c9}@ACME.EXAMPLE", 1);

    /*
     * A row differing by NORMALIZATION as well, not only by case. Every fixture
     * here differed by case, which MySQL's and PostgreSQL's lower() handle
     * correctly -- so a migration batching the rewrite with SQL lower() instead
     * of IdentifierCanonicalizer passed on both, caught only incidentally by
     * SQLite's ASCII-only lower(). No SQL function normalizes Unicode at all, so
     * this is the last place the migration can reimplement canonicalization and
     * get away with it.
     *
     * A DIFFERENT local part, and the reason is the point. This fixture was
     * first written as a decomposed spelling of the row above it -- which
     * canonicalizes to the identical byte string, so it asked two rows of one
     * type to end up sharing a single (type, value). unique(type, value) forbids
     * that, and the two refusal tests below require exactly that shape to be
     * REFUSED, so the test contradicted its own siblings; on MySQL it failed in
     * the fixture rather than the assertion. Uppercase AND decomposed instead,
     * which keeps the normalization axis without asking for a merge: no SQL
     * lower() reaches this row's canonical form on any engine.
     *
     * The coverage here is a property of the PAIR, not of either row. Only row
     * one discriminates a byte strtolower() from a multibyte one, because it is
     * the one holding a precomposed non-ASCII letter -- A-E are ASCII and U+0301
     * is not a letter, so strtolower() followed by normalization canonicalizes
     * this row correctly. Making row one ASCII, or precomposing it, reopens that
     * mutant silently.
     */
    $decomposed = rawIdentifier("ANDRE\u{301}@ACME.EXAMPLE", 2);

    /*
     * One row whose spelling is not canonical is not a collision -- there is
     * nothing to choose between -- so it is rewritten rather than refused.
     *
     * NON-ASCII deliberately. An ASCII row is rewritten correctly by an inlined
     * strtolower(), so a migration that reimplemented canonicalization instead
     * of reusing IdentifierCanonicalizer passed -- and left an accented capital
     * in a spelling the running application can no longer match byte-for-byte.
     */
    runIdentifierMigration();

    expect(DB::table('auth_identifiers')->where('id', $id)->value('value'))
        ->toBe(canonical("JOS\u{c9}@ACME.EXAMPLE"))
        ->and(DB::table('auth_identifiers')->where('id', $decomposed)->value('value'))
        ->toBe(canonical("andr\u{e9}@acme.example"));
});

it('converts every identifier column, not only the identifier table', function (): void {
    if (DB::connection()->getDriverName() === 'sqlite') {
        $this->markTestSkipped('SQLite compares text as bytes; there is no collation to set.');
    }

    revertToLegacyCollation();
    runIdentifierMigration();

    /*
     * All eight. Converting auth_identifiers alone leaves the proof tables with
     * their own opinion about identity, which is where supersession scopes live.
     */
    foreach (convertedColumns() as [$table, $column]) {
        expect(carriesDeterministicCollation($table, $column))
            ->toBeTrue(sprintf('%s.%s must carry the collation this change installs', $table, $column));
    }
});

it('converts to a collation that pads nothing', function (): void {
    if (DB::connection()->getDriverName() !== 'mysql') {
        $this->markTestSkipped('Only MySQL has a deterministic collation that pads; the check is true by construction elsewhere.');
    }

    /*
     * Asked of THIS migration, not of the one that corrects it later. The first
     * collation installed here was utf8mb4_bin, which is PAD SPACE -- so a fresh
     * installation held an engine-dependent equality between running this and
     * running the follow-up, and the collation name lived in two places that could
     * disagree. Pinned here so the upgrade path names one collation and it is the
     * right one.
     */
    revertToLegacyCollation();
    runIdentifierMigration();

    foreach (convertedColumns() as [$table, $column]) {
        expect(comparesWithoutPadding($table, $column))
            ->toBeTrue(sprintf('%s.%s must compare without padding', $table, $column));
    }
});
it('keeps the unique constraints that make the decision enforceable', function (): void {
    revertToLegacyCollation();
    runIdentifierMigration();

    /*
     * A migration that dropped these to avoid the collisions it is supposed to
     * report would pass every other test here. Without them nothing stops two
     * rows for one canonical address, which is the state the whole change
     * exists to make impossible.
     */
    /*
     * The issuance lock table's scope index is not asserted here any more: its
     * scope stopped being an identifier, so the index that enforced one anchor per
     * identifier was replaced by one enforcing one row per bucket. What that table
     * guarantees is asserted where the buckets are.
     */
    expect(indexExists('auth_identifiers', 'auth_identifiers_type_value_unique'))->toBeTrue();

    rawIdentifier('ada@acme.example', 1);

    /*
     * A concrete class, not Throwable. Throwable is an interface, so
     * class_exists() is false and Pest falls back to asserting the exception
     * MESSAGE contains the word "Throwable" -- which no correct implementation
     * can satisfy. The same trap was hit and fixed once already in #41.
     */
    expect(fn (): int => rawIdentifier('ada@acme.example', 2))->toThrow(QueryException::class);
});

it('refuses when two identifier rows would canonicalize onto each other', function (): void {
    revertToLegacyCollation(except: ['auth_identifiers']);
    rawIdentifier('Ada@Acme.Example', 1);
    rawIdentifier('ada@acme.example', 2);

    /*
     * The merge. Two users, two rows, one canonical address -- and no way for
     * Vouch to know which owns it. Writing either would hand one user's
     * credentials to the other's address.
     */
    expect(fn (): null => runIdentifierMigration())->toThrow(IdentifierCollisionsFound::class);
});

it('reports which rows collide, in structured form', function (): void {
    revertToLegacyCollation(except: ['auth_identifiers']);
    $first = rawIdentifier('Ada@Acme.Example', 1);
    $second = rawIdentifier('ada@acme.example', 2);

    /*
     * Structured, not prose. An earlier version asserted the message CONTAINED
     * each row id, which numbers like 1 and 2 satisfy by coincidence -- a
     * variant that mangled the ids to 10 and 20 passed it, and so did one that
     * named rows for auth_identifiers only.
     */
    try {
        runIdentifierMigration();
        $groups = [];
    } catch (IdentifierCollisionsFound $refusal) {
        $groups = $refusal->groups;
    }

    expect($groups)->toHaveCount(1)
        ->and($groups[0]->table)->toBe('auth_identifiers')
        ->and($groups[0]->value)->toBe('ada@acme.example')
        ->and($groups[0]->ids)->toBe([$first, $second]);
});

it('reports colliding rows in the proof tables too', function (): void {
    revertToLegacyCollation();

    // Consumed, so these refuse rather than being deleted as live credentials.
    $first = rawProof('Ada@Acme.Example', consumedAt: (string) now());
    $second = rawProof('ada@acme.example', consumedAt: (string) now());

    try {
        runIdentifierMigration();
        $groups = [];
    } catch (IdentifierCollisionsFound $refusal) {
        $groups = $refusal->groups;
    }

    expect($groups)->toHaveCount(1)
        ->and($groups[0]->table)->toBe('auth_recovery_proofs')
        ->and($groups[0]->ids)->toBe([$first, $second]);
});

it('deletes colliding proofs that are still live', function (): void {
    revertToLegacyCollation();
    rawProof('Ada@Acme.Example');
    rawProof('ada@acme.example');

    /*
     * A live proof is a minute-scale credential, so a collision between two of
     * them costs a user one re-request -- where refusing would block the upgrade
     * on a row nobody can fix, only wait out.
     */
    runIdentifierMigration();

    expect(DB::table('auth_recovery_proofs')->count())->toBe(0);
});

it('refuses rather than deleting a consumed proof', function (): void {
    revertToLegacyCollation();

    /*
     * An innocent non-canonical row in an EARLIER table than the one that refuses.
     * auth_identifiers is scanned first and auth_recovery_proofs last, so this is
     * the only shape that catches a scan which decides and WRITES one table before
     * it has looked at the next: measured, such an implementation is otherwise
     * fully green on SQLite, where the schema half of the refusal contract is
     * skipped, and the row half was pinned nowhere across tables.
     */
    $innocent = rawIdentifier('Grace@Acme.Example', 1);

    rawProof('Ada@Acme.Example', consumedAt: (string) now());
    rawProof('ada@acme.example');

    /*
     * A consumed proof is the record of a redemption, and a burned one of an
     * exhausted guessing budget. Both are permanent by decision elsewhere, so
     * the mixed case refuses rather than quietly rewriting history.
     */
    expect(fn (): null => runIdentifierMigration())->toThrow(IdentifierCollisionsFound::class);

    // The refusal reached back across the table it had already decided.
    expect(DB::table('auth_identifiers')->where('id', $innocent)->value('value'))
        ->toBe('Grace@Acme.Example');
});

it('constructs and refuses a split in the proof tables', function (): void {
    if (DB::connection()->getDriverName() !== 'mysql') {
        $this->markTestSkipped('Only an accent-insensitive collation makes two rows one address.');
    }

    revertToLegacyCollation();

    /*
     * Built HERE rather than in auth_identifiers, where unique(type, value)
     * rejects the second insert under ai_ci -- the index is what makes a split
     * unconstructible there, on every engine and in both collation states.
     *
     * These two rows are one address to the current collation and two after the
     * change, so proofs that were one account's become divided. Consumed, so the
     * refusal is about the split rather than about live-credential cleanup.
     */
    $first = rawProof("jos\u{e9}@acme.example", consumedAt: (string) now());
    $second = rawProof('jose@acme.example', consumedAt: (string) now());

    $equal = DB::table('auth_recovery_proofs')
        ->where('identifier_value', 'jose@acme.example')->count();

    // The premise: this engine really does consider them one address right now.
    expect($equal)->toBe(2);

    try {
        runIdentifierMigration();
        $groups = [];
    } catch (IdentifierCollisionsFound $refusal) {
        $groups = $refusal->groups;
    }

    $reported = [];

    foreach ($groups as $group) {
        $reported = array_merge($reported, $group->ids);
    }

    sort($reported);

    expect($groups)->not->toBe([])
        ->and($reported)->toBe([$first, $second]);
});

it('changes neither rows nor schema when it refuses', function (): void {
    revertToLegacyCollation(except: ['auth_identifiers']);
    $id = rawIdentifier('Ada@Acme.Example', 1);
    rawIdentifier('ada@acme.example', 2);

    /*
     * An INNOCENT non-canonical row alongside the colliding pair. With only the
     * pair present, a migration that rewrote every row and validated afterwards
     * had nothing to be caught rewriting and passed this test.
     */
    $innocent = rawIdentifier('Grace@Acme.Example', 3);

    try {
        runIdentifierMigration();
    } catch (IdentifierCollisionsFound) {
        // Expected; what matters is the state left behind.
    }

    /*
     * The SCHEMA as well as the rows. A migration that converted all eight
     * columns and then refused passed a row-only assertion -- so an operator who
     * fixed the reported rows and re-ran would be running against a database
     * already half-changed, with no way to tell.
     */
    expect(DB::table('auth_identifiers')->where('id', $id)->value('value'))
        ->toBe('Ada@Acme.Example')
        ->and(DB::table('auth_identifiers')->where('id', $innocent)->value('value'))
        ->toBe('Grace@Acme.Example');

    /*
     * And no TABLE left behind either. A scan bounded by persisting its working set
     * has somewhere to leave residue that a row-and-column assertion cannot see.
     *
     * Against the declared set, not against a baseline taken here: the migration has
     * already run in setUp, so residue from THAT run is in any baseline this body
     * could capture and a diff is empty however much was left behind -- measured.
     */
    expect(tableNames())->toBe(expectedTableNames());

    if (DB::connection()->getDriverName() === 'sqlite') {
        return;
    }

    /*
     * By NAME. PostgreSQL reports 'default' for an unaltered column rather than
     * NULL, and the default is itself deterministic, so asking "is it
     * deterministic" returned true in every state and this assertion could
     * never hold there -- measured against a correct implementation.
     */
    expect(carriesDeterministicCollation('auth_recovery_proofs', 'identifier_value'))->toBeFalse();
});

it('detects collisions without scanning pair by pair', function (): void {
    revertToLegacyCollation();

    for ($i = 0; $i < 40; $i++) {
        rawIdentifier(sprintf('user-%d@acme.example', $i), $i + 1);
    }

    /*
     * Bounded, because nothing else stops an O(n squared) implementation: a
     * query per candidate pair passes every other test here and would never
     * finish on a real installation. Forty rows make 780 pairs, so the ceiling
     * separates a set-based detection from a pairwise one without pinning the
     * exact SQL.
     */
    $queries = 0;
    DB::listen(function () use (&$queries): void {
        $queries++;
    });

    runIdentifierMigration();

    /*
     * This bounds QUERY SHAPE, not algorithmic complexity: a scan that reads
     * every row once and then compares pairs in PHP issues no extra statements
     * and passes. Stated rather than left implied, because the distinction is
     * the difference between what this test proves and what it appears to.
     */
    expect($queries)->toBeLessThan(120);
});

/** Insert a verification row directly, in whatever spelling is asked for. */
function rawVerification(string $value, ?string $burnedAt = null): int
{
    return (int) DB::table('auth_identifier_verifications')->insertGetId([
        'identifier_type' => 'email',
        'identifier_value' => $value,
        'code_hash' => 'hash-' . bin2hex(random_bytes(4)),
        'is_decoy' => false,
        'attempts' => 0,
        'expires_at' => now()->addMinutes(5),
        'burned_at' => $burnedAt,
        'created_at' => now(),
        'updated_at' => now(),
    ]);
}

it('scans every table in one run, not the first that has rows', function (): void {
    revertToLegacyCollation(except: ['auth_identifiers']);

    // A clean identifier row AND a colliding consumed pair elsewhere. Every
    // other proof test here runs against an empty auth_identifiers, so a scan
    // that stopped once it had looked at identifiers was never caught.
    rawIdentifier('ada@acme.example', 1);
    $first = rawProof('Grace@Acme.Example', consumedAt: (string) now());
    $second = rawProof('grace@acme.example', consumedAt: (string) now());

    try {
        runIdentifierMigration();
        $groups = [];
    } catch (IdentifierCollisionsFound $refusal) {
        $groups = $refusal->groups;
    }

    expect($groups)->toHaveCount(1)
        ->and($groups[0]->table)->toBe('auth_recovery_proofs')
        ->and($groups[0]->ids)->toBe([$first, $second]);
});

it('triages the verification table on the same terms', function (): void {
    revertToLegacyCollation();

    rawVerification('Ada@Acme.Example');
    rawVerification('ada@acme.example');

    // The other transient table, on the same policy. It appeared only in the
    // collation loop before, so its triage path was untested.
    runIdentifierMigration();

    expect(DB::table('auth_identifier_verifications')->count())->toBe(0);
});

it('refuses rather than deleting a burned verification', function (): void {
    revertToLegacyCollation();

    /*
     * BURNED, not consumed. #31 made an exhausted guessing budget terminal for
     * the same reason #38 made supersession permanent, and the prose here named
     * both while only consumption was ever exercised.
     */
    rawVerification('Ada@Acme.Example', burnedAt: (string) now());
    rawVerification('ada@acme.example');

    expect(fn (): null => runIdentifierMigration())->toThrow(IdentifierCollisionsFound::class);
});

it('rewrites rows without a statement per row', function (): void {
    revertToLegacyCollation();

    for ($i = 0; $i < 40; $i++) {
        rawIdentifier(sprintf('USER-%d@ACME.EXAMPLE', $i), $i + 1);
    }

    /*
     * Forty rows that all NEED rewriting, which the detection bound does not
     * cover: that test seeds already-canonical rows, so zero updates happen and
     * a per-row UPDATE loop is invisible there.
     *
     * This bounds the WRITE shape. Neither test bounds algorithmic complexity --
     * a scan held in PHP memory issues no statements at all -- and that limit is
     * stated rather than pretended away.
     */
    $writes = 0;
    DB::listen(function ($query) use (&$writes): void {
        if (str_starts_with(strtolower(ltrim($query->sql)), 'update')) {
            $writes++;
        }
    });

    runIdentifierMigration();

    expect($writes)->toBeLessThan(20)
        ->and(DB::table('auth_identifiers')->where('value', 'user-0@acme.example')->exists())
        ->toBeTrue();
});

it('reports collisions from every table that has them', function (): void {
    revertToLegacyCollation(except: ['auth_identifiers']);

    rawIdentifier('Ada@Acme.Example', 1);
    rawIdentifier('ada@acme.example', 2);
    rawProof('Grace@Acme.Example', consumedAt: (string) now());
    rawProof('grace@acme.example', consumedAt: (string) now());

    /*
     * Two tables at once, which nothing here had. A report carrying only the
     * first group passed everything: the operator fixes what was named,
     * re-runs, and is refused again over something the first report already
     * knew about.
     */
    try {
        runIdentifierMigration();
        $groups = [];
    } catch (IdentifierCollisionsFound $refusal) {
        $groups = $refusal->groups;
    }

    $tables = [];

    foreach ($groups as $group) {
        $tables[] = $group->table;
    }

    sort($tables);

    expect($tables)->toBe(['auth_identifiers', 'auth_recovery_proofs']);
});

/*
 * #61. The scan read every row of every identifier table into PHP before
 * deciding anything, so peak memory grew with the largest installation rather
 * than with a working set. Measured on the array shape it built: 857 bytes per
 * row, linear -- so roughly 157k auth_identifiers rows exhausted a 128 MB limit
 * and a large host could not complete the upgrade at all.
 *
 * The two tests already in this file that bound statement counts say in their
 * own comments that they do not bound this: "a scan held in PHP memory issues no
 * statements at all". These are the other half.
 *
 * What makes chunking more than a loop change is the grouping. A group is the
 * transitive closure of two relations -- rows sharing a canonical form, and rows
 * the CURRENT collation already equates -- and a group can be reached through
 * either. Chunk naively and one group becomes several, which does not report a
 * smaller collision: it reports NO collision, converts rows that should have
 * refused, and merges accounts. So the straddle fixtures below are the point of
 * the issue rather than decoration.
 *
 * They place the colliding rows at opposite ends of a wide id range with filler
 * between, rather than reading a chunk size from the implementation. That keeps
 * them independent of how it chunks, at the cost of one stated assumption: a
 * chunk larger than STRADDLE_GAP would hold the pair together and the test would
 * still pass while proving less.
 */

const STRADDLE_GAP = 1200;

/**
 * Insert $count filler identifiers whose ids sit between two colliding rows.
 *
 * Batched, because these tests seed more rows than the rest of this file put
 * together and a per-row insert makes them the slowest thing in the suite on
 * MySQL. The values are already canonical, so the filler contributes no
 * collisions and no rewrites of its own.
 */
function straddleFiller(int $count, int $firstUserId): void
{
    $now = (string) now();

    foreach (array_chunk(range(0, $count - 1), 250) as $batch) {
        $rows = [];

        foreach ($batch as $offset) {
            $rows[] = [
                'user_id' => $firstUserId + $offset,
                'type' => 'email',
                /*
                 * "aaa-", not "filler-", and the prefix is load-bearing. An
                 * implementation may page by the unique(type, value) index rather than
                 * by id, and under the deterministic collation 'Ada@' and 'ada@' are
                 * adjacent in that order with every 'filler-' row after them -- so the
                 * colliding pair shared a page and a per-chunk closure PASSED this
                 * test. 'aaa-' sorts strictly between them, which straddles both
                 * orderings. Measured: with it, a per-chunk closure fails.
                 */
                'value' => sprintf('aaa-%d@acme.example', $firstUserId + $offset),
                'verified_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        DB::table('auth_identifiers')->insert($rows);
    }
}

/**
 * Insert $count filler proofs, so ids in the PROOF table are pushed apart.
 *
 * A separate helper rather than a parameter on the one above, because the two
 * tables are what the distinction is about: filler in auth_identifiers does not
 * move auth_recovery_proofs' ids at all, and a straddle test seeded with the
 * wrong one quietly becomes a test of two adjacent rows. Measured -- that is
 * exactly what the first version of the split tests below did, and the id
 * premise is what caught it.
 */
function straddleProofFiller(int $count, int $offset): void
{
    $now = (string) now();
    $expires = (string) now()->addMinutes(5);

    foreach (array_chunk(range(0, $count - 1), 250) as $batch) {
        $rows = [];

        foreach ($batch as $index) {
            $rows[] = [
                'identifier_type' => 'email',
                'identifier_value' => sprintf('proof-filler-%d@acme.example', $offset + $index),
                'code_hash' => sprintf('hash-%d-%d', $offset, $index),
                'is_decoy' => false,
                'attempts' => 0,
                'expires_at' => $expires,
                'consumed_at' => $now,
                'burned_at' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        DB::table('auth_recovery_proofs')->insert($rows);
    }
}

/**
 * Every row id any refusal named, sorted.
 *
 * Catches only IdentifierCollisionsFound, deliberately. An implementation that
 * failed to group a straddling pair does not refuse at all -- it proceeds to the
 * rewrite and dies on the unique index, so the diagnostic is a constraint
 * violation escaping from here rather than a mismatched id list. Widening the
 * catch would turn that into a quiet empty array.
 *
 * @return list<int>
 */
function refusedIds(): array
{
    try {
        runIdentifierMigration();

        return [];
    } catch (IdentifierCollisionsFound $refusal) {
        $ids = [];

        foreach ($refusal->groups as $group) {
            $ids = array_merge($ids, $group->ids);
        }

        sort($ids);

        return $ids;
    }
}

it('closes a merge whose rows are a whole table apart', function (): void {
    /*
     * auth_identifiers stays on the deterministic collation so both spellings can
     * be inserted -- under the legacy one its unique index rejects the second,
     * which is what makes a merge constructible here and a split not.
     */
    revertToLegacyCollation(except: ['auth_identifiers']);

    $first = rawIdentifier('Ada@Acme.Example', 1);
    straddleFiller(STRADDLE_GAP, 100);
    $second = rawIdentifier('ada@acme.example', 2);

    // The premises: far apart by id, AND separated in value order, so neither a
    // scan that pages by primary key nor one that pages by the unique index can
    // see the pair without reaching across a chunk.
    expect($second - $first)->toBeGreaterThan(STRADDLE_GAP);
    expect(DB::table('auth_identifiers')
        ->whereBetween('value', ['Ada@Acme.Example', 'ada@acme.example'])
        ->count())->toBeGreaterThan(STRADDLE_GAP);

    /*
     * And the conclusion. A scan that lost the closure across chunks does not
     * report a smaller collision here -- it reports NONE, and then canonicalizes
     * two accounts' identifiers onto each other.
     */
    expect(refusedIds())->toBe([$first, $second]);
});

it('closes a split whose rows are a whole table apart', function (): void {
    if (DB::connection()->getDriverName() !== 'mysql') {
        $this->markTestSkipped('Only an accent-insensitive collation makes two spellings one address.');
    }

    revertToLegacyCollation();

    /*
     * The other relation, and the one no amount of PHP can discover: these two
     * are one address to the current collation and two after the change. In a
     * proof table because auth_identifiers' unique index rejects the second
     * insert, and consumed so the refusal is about the split rather than about
     * live-credential cleanup.
     */
    $first = rawProof("jos\u{e9}@acme.example", consumedAt: (string) now());
    straddleProofFiller(STRADDLE_GAP, 100);
    $second = rawProof('jose@acme.example', consumedAt: (string) now());

    expect($second - $first)->toBeGreaterThan(STRADDLE_GAP);
    // The premise: this engine really does consider them one address right now.
    expect(DB::table('auth_recovery_proofs')->where('identifier_value', 'jose@acme.example')->count())->toBe(2);

    expect(refusedIds())->toBe([$first, $second]);
});

/*
 * WHAT IS NOT TESTED HERE, because it cannot be constructed.
 *
 * A group needing BOTH relations to reach -- canonical from one row, loose from
 * the next -- was drafted as a third straddle case and removed. The canonicalizer
 * is lower() plus NFC, and an accent-insensitive collation folds strictly more
 * than that, so two rows with one canonical form are always in one loose class
 * too. Measured on MySQL 8 / utf8mb4_0900_ai_ci: NFC vs NFD, NFC vs unaccented
 * and NFD vs unaccented all compare equal, so the loose relation CONTAINS the
 * canonical one on an accent-insensitive column, and on a deterministic column
 * byte equality is contained in it. Either way one relation dominates and no
 * fixture can require both.
 *
 * The union in components() is still right, and is not dead: the dominance is a
 * property of THIS canonicalizer, not of the design. A canonicalization step an
 * accent-insensitive collation does not fold -- trimming, punycode, anything
 * touching more than case and accents -- makes the two relations independent
 * again, and the union is what keeps the closure correct when that happens.
 *
 * A draft that claimed to test this case would have been a second split straddle
 * with a third row and 1200 more filler rows, proving nothing the case above does
 * not, while its comment said otherwise.
 */

it('names every row of a group of three', function (): void {
    /*
     * Group SIZE rather than straddling, and it needs no filler: three byte-distinct
     * spellings of one canonical form, all accepted by unique(type, value) while the
     * column is still deterministic.
     *
     * What it catches is a plausible way to bound a working set -- keep two rows per
     * canonical key, on the reasoning that two different spellings is already a
     * collision and the rest are redundant. Measured, that passes every other test in
     * this file on SQLite and MySQL while reporting an incomplete id list: the
     * operator reconciles the rows named, re-runs, and is refused again over a row the
     * first report already knew about.
     *
     * Under the transient policy it is worse than a short report. A live group whose
     * only terminal member is the row that got dropped reads as non-terminal, so rows
     * that should have refused are DELETED instead.
     */
    revertToLegacyCollation(except: ['auth_identifiers']);

    $first = rawIdentifier('Ada@Acme.Example', 1);
    $second = rawIdentifier('ada@acme.example', 2);
    $third = rawIdentifier('ADA@ACME.EXAMPLE', 3);

    // The premise: all three really are stored distinctly, so a complete report has
    // three rows to name rather than two the engine already folded.
    expect(DB::table('auth_identifiers')->count())->toBe(3);

    expect(refusedIds())->toBe([$first, $second, $third]);
});

it('keeps its statement count bounded when the table is large', function (): void {
    /*
     * A chunked scan buys bounded memory with statements, and nothing else stops
     * it spending them a row at a time. The existing bound in this file is
     * measured on forty rows, where a chunk of one is invisible; this one seeds
     * enough that a degenerate chunk costs thousands of statements.
     *
     * The same NUMBER as the pairwise-detection test, but not the same claim: that
     * one bounds query SHAPE on forty rows, this one bounds RATE on twelve hundred.
     * What 120 permits here is roughly one statement per ten rows. Measured against
     * a correct chunked implementation: 33 statements at a chunk of 500, and 96 at a
     * chunk of 50, so the ceiling rejects a chunk below about forty. No plausible
     * design goes there, and the margin is stated rather than left to be rediscovered
     * by whoever trips it.
     */
    revertToLegacyCollation();
    straddleFiller(STRADDLE_GAP, 100);

    $queries = 0;
    DB::listen(function () use (&$queries): void {
        $queries++;
    });

    runIdentifierMigration();

    /*
     * The control first. Without it a DB::listen that never fired, or an up() that
     * did nothing, satisfies the ceiling -- which is the shape of the forty-row
     * bound this is modelled on, carried over rather than noticed.
     */
    expect($queries)->toBeGreaterThan(0);
    // And the work really happened: the filler is canonical, so it survives intact.
    expect(DB::table('auth_identifiers')->count())->toBe(STRADDLE_GAP);

    expect($queries)->toBeLessThan(120);
});

it('decides in memory that does not grow with the table', function (): void {
    /*
     * The measurement the issue is about, and the only one of these tests that is
     * red before the change. Ten thousand rows cost 22 MB under the scan that read
     * them all -- 4 MB of baseline plus about 1.8 KB a row, linear and verified at
     * 1k, 2k, 8k and 20k -- so a 16 MB limit refuses it. A scan that decides in
     * chunks stays near its baseline whatever the row count.
     *
     * A HUNDRED thousand rows, which matters more than it looks. At ten thousand a
     * chunk sized as a FRACTION of the table passes -- measured, a chunk of 6000
     * fits under this limit -- so the test would have certified "the scan holds
     * about half the table" rather than "memory does not grow with it". At a
     * hundred thousand the same fraction is ten times the limit.
     *
     * It costs almost nothing, now that the fixture declares the unique index the
     * loose-class subquery needs: the whole run is a fraction of a second, where
     * ten thousand rows without that index took nearly four.
     */
    if (! upgradeFixtureIsMeasurable()) {
        $this->markTestSkipped('The upgrade fixture is standalone SQLite; another engine would measure it again.');
    }

    $run = upgradeFixtureRun('16M', 100000, 'canonical');

    /*
     * The surviving row count and each row's own expected value, so an upgrade that
     * "succeeded" by emptying the table, by refusing without working, or by moving
     * identifiers between subjects is a different answer rather than the same one.
     * Both come back through the same helper the uppercase case below uses; here they
     * agree trivially because these rows were already canonical, which is the point
     * of keeping this shape separate from that one.
     */
    expect($run['rows'])->toBe(100000);
    expect($run['expected'])->toBe(100000);
});

/**
 * Whether running the standalone fixture here would measure anything new.
 *
 * It builds its OWN SQLite connection and never touches the configured one, so under
 * VOUCH_TEST_DB=mysql or pgsql it measured exactly the same number a second and third
 * time -- about five minutes per engine for one result. #101's saving, not a limitation.
 */
function upgradeFixtureIsMeasurable(): bool
{
    return DB::connection()->getDriverName() === 'sqlite';
}

/**
 * Run the upgrade fixture and return what it reported.
 *
 * Skipped unless the suite is on SQLite, and that is the #101 saving rather than a
 * limitation: the fixture builds its OWN standalone SQLite connection and never touches
 * the configured one, so running it under VOUCH_TEST_DB=mysql measured exactly the same
 * number a third time. Three engines paid about five minutes each for one measurement.
 *
 * `milliseconds` is reported but no longer ASSERTED on: the time-growth case that read it was
 * removed after measuring 4.56x on CI for a correct implementation. It is kept because
 * docs/operations.md quotes runtime figures an operator plans a window from, and this is where
 * those numbers come from — a measurement to read, not a gate to pass.
 *
 * @return array{rows: int, expected: int, peak: int, milliseconds: int}
 */
function upgradeFixtureRun(string $limit, int $rows, string $shape): array
{
    /*
     * Cached per process, because two cases assert on the SAME pair of runs -- one about
     * memory, one about time -- and each 400 000-row run costs minutes. Caching rather
     * than merging the cases keeps each runnable under --filter on its own.
     */
    static $runs = [];

    $key = $limit . '/' . $rows . '/' . $shape;

    if (isset($runs[$key])) {
        return $runs[$key];
    }

    $result = phpUnderMemoryLimit(
        $limit,
        dirname(__DIR__) . '/Fixtures/identifier-upgrade-scan.php',
        dirname(__DIR__, 2),
        (string) $rows,
        $shape,
    );

    expect($result['status'])->toBe(0, 'the upgrade must complete at ' . $rows . ' rows under ' . $limit);

    $reported = explode(' ', trim($result['output']));

    expect($reported)->toHaveCount(4);

    return $runs[$key] = [
        'rows' => (int) $reported[0],
        'expected' => (int) $reported[1],
        'peak' => (int) $reported[2],
        'milliseconds' => (int) $reported[3],
    ];
}

it('rewrites a whole table of non-canonical identifiers in memory that does not grow', function (): void {
    /*
     * #92, and the half of the bound that was missing. #61 stopped the SCAN holding
     * the table; the rewrite still accumulated one (stored, canonical) pair per
     * distinct changing spelling, and when no identifier is canonical that is one
     * pair per row. The fixture used to record that growth as "by design", which was
     * true of the deduplication and false of the conclusion: a host whose identifiers
     * are not yet canonical is precisely the host the migration is for. Measured
     * against the accumulating rewrite: 100 000 rows peaked at 45 MiB over a 6 MiB
     * baseline and succeeded only at 128 MB, and 400 000 exhausted even that.
     *
     * GROWTH is the property, so the two runs are COMPARED rather than each merely
     * fitting under the limit. One size cannot tell bounded from cheaper: an
     * accumulator holding every pair in length-prefixed compressed batches retained
     * 0.765 MiB at 100 000 rows and 3.128 MiB at 400 000, passed both, and died only
     * at 1.6M -- linear with a smaller constant, which is what #61 already did once
     * for the scan.
     *
     * Two megabytes of slack, one step of this allocator's granularity, since the
     * observed peaks move in 2 MiB increments. A spooled implementation reports the
     * same peak at both sizes.
     *
     * What makes that comparison work is the fixture's HASH-DERIVED values, and the
     * limit of it is worth stating because an earlier version of this comment
     * overclaimed. memory_get_peak_usage(true) is an allocator high-water mark, not a
     * measure of retained data: measured, pairs retained in a compressed php://memory
     * stream quadrupled their retained bytes between these two sizes while reporting
     * 8 MiB for both, and passed this comparison with ZERO slack. The fixture's
     * entropy is what forces retained growth to show up as allocation at these sizes
     * -- hex and a shared domain still compress somewhat, so the claim is "far less
     * compressible", not "incompressible".
     *
     * And even then: two finite sizes are a regression guard, not a proof of
     * asymptotic boundedness. Whether the implementation actually streams is settled
     * by reading it, which is where that claim belongs.
     *
     * The second number is each row's OWN expected value, derived from the identity it
     * was seeded with. A count of canonical-LOOKING rows passed a mutant that rotated
     * targets within each batch: every row lower-case, 99 500 of 100 000 belonging to
     * the wrong subject. An identifier moved to another owner is worse than one left
     * un-canonicalized.
     */
    if (! upgradeFixtureIsMeasurable()) {
        $this->markTestSkipped('The upgrade fixture is standalone SQLite; another engine would measure it again.');
    }

    $small = upgradeFixtureRun('16M', 100000, 'uppercase');
    $large = upgradeFixtureRun('16M', 400000, 'uppercase');

    expect($small['rows'])->toBe(100000);
    expect($small['expected'])->toBe(100000);
    expect($large['rows'])->toBe(400000);
    expect($large['expected'])->toBe(400000);

    // The premise: the fixture really did report a peak, so the comparison below is
    // not between two zeros.
    expect($small['peak'])->toBeGreaterThan(0);

    expect($large['peak'])->toBeLessThanOrEqual($small['peak'] + 2 * 1024 * 1024);
});

/*
 * #101's time-growth case USED TO BE HERE, and removing it is a correction rather than a
 * retreat from the property.
 *
 * It sampled 100 000 / 200 000 / 400 000 rows and bounded each doubling at 3, on the reasoning
 * that linear predicts 2 and quadratic 4. Locally that held: three rounds measured 2.36-2.58
 * and 2.29-2.35 against the defect's 2.67 and 3.85.
 *
 * On CI it measured **4.56x** on macOS and **3.54x** on Ubuntu, both on the first doubling and
 * both for the correct implementation -- one of them worse than quadratic predicts, and worse
 * than the defect ever measured locally. Two independent runners, two ratios, neither near the
 * local 2.4-2.6.
 *
 * Both inflated on 100 000 -> 200 000 rather than 200 000 -> 400 000, which is the tell: the
 * 100 000 run is the shortest and the most exposed to fixed overhead and cache state, so a
 * ratio taken from it is the least stable of the two. The gate rested on the weaker number.
 *
 * A shared runner's variance is therefore larger than the signal the assertion was reading, and
 * the bound could not be widened into usefulness either: anything above 4 admits quadratic
 * outright. Meanwhile the case had begun failing unrelated pull requests on main.
 *
 * What replaced it is not nothing. The plan assertion below is deterministic and checks the
 * mechanism #101 is actually about -- that the update seeks the (type, value) index rather than
 * scanning -- and `rewrites a whole table of non-canonical identifiers in memory that does not
 * grow` still compares peak allocation across two sizes, which is a measurement a runner does
 * not perturb. The runtime claim lives in docs/operations.md, where it is an operator's
 * planning number rather than a gate.
 *
 * The lesson is worth the lines: a wall-clock ratio is not a property you can assert on
 * hardware you do not control, however carefully the bound is derived.
 */

/**
 * The UPDATE target of $sql: which of the upgrade's tables it writes, and the names a plan
 * step may use for it.
 *
 * The TARGET specifically, not every relation the statement mentions, and that distinction
 * is the whole point. Collecting every table and alias let a SOURCE relation's indexed
 * access satisfy the non-empty check while the target's own scan went unattributed:
 * measured, `update main.auth_identifiers from … as matched` reported
 * `SEARCH matched … (type=? AND value=?)` beside `SCAN main.auth_identifiers`, and passed.
 *
 * Schema qualification counts in both directions. `main.` alone made a correct
 * implementation's 36 indexed updates read as "no readable target access path", because
 * SQLite reports `SEARCH main.auth_identifiers …` and the matcher wanted the bare name.
 *
 * @return array{table: string, names: list<string>}|null
 */
function planUpdateTarget(string $sql): ?array
{
    $quoted = '[`"\[]?';
    $endQuote = '[`"\]]?';
    $pattern = '/^\s*update\s+(?:' . $quoted . '(\w+)' . $endQuote . '\s*\.\s*)?'
        . $quoted . '(\w+)' . $endQuote . '(?:\s+(?:as\s+)?' . $quoted . '(\w+)' . $endQuote . ')?/i';

    if (preg_match($pattern, $sql, $matches) !== 1) {
        return null;
    }

    $schema = $matches[1];
    $table = strtolower($matches[2]);
    $alias = strtolower($matches[3] ?? '');

    if (! array_key_exists($table, UPGRADE_TABLES)) {
        return null;
    }

    $names = [$table];

    if ($schema !== '') {
        $names[] = strtolower($schema) . '.' . $table;
    }

    /*
     * An alias only if it is not a keyword: `update auth_identifiers set …` would otherwise
     * read `set` as the alias, and anything named `set` in a plan would then count.
     */
    if ($alias !== '' && ! in_array($alias, ['set', 'where', 'from', 'as'], true)) {
        $names[] = $alias;
    }

    return ['table' => $table, 'names' => $names];
}

/** What planDetails() reports for a step it cannot read; callers must fail on it. */
const UNREADABLE_PLAN_STEP = 'a step with no readable detail';

/**
 * The plan TREE SQLite reports for a captured statement, as id/parent/detail rows.
 *
 * An unreadable step is reported as such rather than skipped: a detail this cannot read is
 * a result it cannot interpret, and reading it as agreement is how an absence-based version
 * of these assertions let `+value` through.
 *
 * The tree, not a flat list, because the SHAPE carries the distinction that matters: a
 * two-column lookup inside a `LIST SUBQUERY` says nothing about how the UPDATE reaches its
 * target rows. Measured -- an update whose target full-scans while a nested subquery does
 * the indexed lookup satisfied a flat any-step match and passed the whole file.
 *
 * @param  array{sql: string, bindings: array<array-key, mixed>}  $statement
 * @return list<array{id: int, parent: int, detail: string}>
 */
function planDetails(array $statement): array
{
    $steps = [];

    foreach (DB::select('explain query plan ' . $statement['sql'], $statement['bindings']) as $step) {
        $detail = is_object($step) && property_exists($step, 'detail') ? $step->detail : null;
        $id = is_object($step) && property_exists($step, 'id') ? $step->id : null;
        $parent = is_object($step) && property_exists($step, 'parent') ? $step->parent : null;

        $steps[] = [
            'id' => is_numeric($id) ? (int) $id : -1,
            'parent' => is_numeric($parent) ? (int) $parent : -1,
            'detail' => is_string($detail) ? $detail : UNREADABLE_PLAN_STEP,
        ];
    }

    return $steps;
}

/**
 * The access paths the statement itself uses to reach its TARGET rows.
 *
 * An access is a step that actually reads something -- SCAN or SEARCH -- and it belongs to
 * the target unless some ancestor marks a subquery. Everything else in a plan is structure:
 * `MULTI-INDEX OR`, `INDEX 1`, `CO-ROUTINE`, `LIST SUBQUERY`.
 *
 * Classified by what a step IS rather than by how deep it sits, and that is a correction.
 * Treating parent 0 as "the target" returned SQLite's `INDEX 1` and `INDEX 2` wrapper nodes
 * for a batched OR and missed the searches beneath them -- rejecting, measured, exactly the
 * correct form it was written to admit, with 72 wrapper-node violations. It also read a
 * parent-0 `LIST SUBQUERY` marker as an access. Depth says nothing; the kind of step and
 * whether a subquery encloses it say everything.
 *
 * Restricted to accesses naming the TARGET relation, resolved through the statement's
 * aliases, because an unnested read is not necessarily a read of the target: measured,
 * `update … from (values …)` reports `SCAN 200-ROW VALUES CLAUSE` at parent zero beside a
 * perfectly indexed target search, and rejecting that rejected a correct implementation.
 *
 * Callers must also require the result to be NON-EMPTY. Narrowing by name reintroduces the
 * risk that an alias spelling this cannot read makes a genuine target scan invisible -- a
 * bracket-quoted `[t]` did exactly that once -- and failing when no access can be attributed
 * is what keeps that from passing quietly.
 *
 * @param  list<array{id: int, parent: int, detail: string}>  $plan
 * @param  list<string>  $relations
 * @return list<string>
 */
function planTargetAccess(array $plan, array $relations): array
{
    $byId = [];

    foreach ($plan as $step) {
        $byId[$step['id']] = $step;
    }

    $access = [];

    foreach ($plan as $step) {
        if (preg_match('/^(SCAN|SEARCH)\b/', $step['detail']) !== 1) {
            continue;
        }

        // Walk to the root; any subquery marker on the way means this read belongs to the
        // subquery rather than to the update's own target.
        $nested = false;
        $parent = $step['parent'];
        $guard = 0;

        while ($parent > 0 && isset($byId[$parent]) && $guard < 32) {
            if (preg_match('/SUBQUERY|CO-ROUTINE/', $byId[$parent]['detail']) === 1) {
                $nested = true;

                break;
            }

            $parent = $byId[$parent]['parent'];
            $guard++;
        }

        if ($nested) {
            continue;
        }

        foreach ($relations as $relation) {
            if (preg_match('/^(SCAN|SEARCH)\\s+(?:\\w+\\.)?[`"\\[]?' . preg_quote($relation, '/') . '[`"\\]]?\\b/i', $step['detail']) === 1) {
                $access[] = $step['detail'];

                break;
            }
        }
    }

    return $access;
}

/**
 * The three tables the upgrade reads and rewrites, each with its own column pair.
 *
 * The pair is not the same in all three, and assuming it was would have REJECTED a correct
 * implementation: measured against an indexed control, 24 valid plans reported
 * `(identifier_type=? AND identifier_value=?)` and failed an assertion demanding
 * `type=? AND value=?`. Excluding a correct fix is as much a defect in a spec as admitting
 * a wrong one.
 *
 * @var array<string, array{string, string}>
 */
const UPGRADE_TABLES = [
    'auth_identifiers' => ['type', 'value'],
    'auth_identifier_verifications' => ['identifier_type', 'identifier_value'],
    'auth_recovery_proofs' => ['identifier_type', 'identifier_value'],
];

/**
 * Seed every table the upgrade touches with non-canonical rows, cycling three types.
 *
 * All THREE, because an implementation indexed only for the account table left both
 * credential tables scanning and nothing noticed -- the listener looked at one table and the
 * standalone fixture created the other two without seeding them.
 */
function upgradeFillerAcrossTables(int $count, int $firstUserId): void
{
    $now = (string) now();
    $types = ['email', 'EMAIL', 'Username'];

    uppercaseFiller($count, $firstUserId);

    foreach (array_chunk(range(0, $count - 1), 250) as $batch) {
        $verifications = [];
        $proofs = [];

        foreach ($batch as $offset) {
            $type = $types[$offset % count($types)];
            $value = sprintf('AAA-%d@ACME.EXAMPLE', $firstUserId + $offset);
            $row = [
                'identifier_type' => $type,
                'identifier_value' => $value,
                'is_decoy' => false,
                'attempts' => 0,
                'expires_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];

            $verifications[] = $row + ['code_hash' => 'v-' . $firstUserId . '-' . $offset];
            $proofs[] = $row + ['code_hash' => 'p-' . $firstUserId . '-' . $offset];
        }

        DB::table('auth_identifier_verifications')->insert($verifications);
        DB::table('auth_recovery_proofs')->insert($proofs);
    }
}

it('rewrites through the deterministic index rather than scanning for each chunk', function (): void {
    /*
     * #101's mechanism, and the SCOPE of this case is part of its contract.
     *
     * It is a REGRESSION GUARD on the shipped implementation's SQLite target lookups, not a
     * certificate that every correct implementation passes. A future rewrite in a different
     * legitimate shape may need this assertion updated, and that is expected rather than a
     * failure of the guard. What it protects is the thing #101 is about: `where value in (…)`
     * cannot use an index on (type, value), the plan proves the shipped fix does, and a
     * regression shows up here.
     *
     * That scope is not modesty, it is the measured boundary. Trying to decide "this UPDATE
     * is index-served" by reading one engine's plan rejected SEVEN legitimate spellings over
     * as many rounds of review, each admitted in turn and followed by another:
     *
     *   reversed conjuncts; a batched `(type = ? AND value IN (…)) OR (…)`; a shared value
     *   constraint as `(type = ? OR type = ?) AND value IN (…)`; MULTI-INDEX OR's `INDEX n`
     *   wrapper nodes; an indexed lookup inside a LIST SUBQUERY while the target scanned; a
     *   bounded `UPDATE … FROM (VALUES …)` input; and a schema-qualified `main.` target.
     *
     * There are unboundedly many ways to write a correctly indexed update, so an eighth fix
     * would not have ended that. The list is here so the next reader sees the boundary
     * rather than rediscovering it.
     *
     * The implementation-agnostic claims carry the rest and needed no narrowing: every
     * subject's exact type and value on all three engines, flat memory, the statement
     * ceiling, and time growth per doubling.
     */
    revertToLegacyCollation();

    /*
     * Four pages of 500 across all three tables, so the captured statements include more
     * than one chunk per table and the plan assertion sees every one of them rather than a
     * single lucky statement.
     */
    upgradeFillerAcrossTables(2000, 100);

    $observed = [];
    DB::listen(function (QueryExecuted $query) use (&$observed): void {
        $observed[] = ['sql' => $query->sql, 'bindings' => $query->bindings];
    });

    runIdentifierMigration();

    /*
     * FROZEN here, and that is not tidiness. The listener is still attached while the
     * assertions below run their own EXPLAINs, so reading the live array fed those
     * statements back into themselves: measured, `explain query plan explain query plan
     * update …` and a syntax error. What is under test is what the MIGRATION ran.
     */
    $statements = $observed;

    // The premise: the migration ran and the work landed, on every table.
    expect($statements)->not->toBe([]);
    expect(DB::table('auth_identifiers')->where('value', 'aaa-100@acme.example')->exists())->toBeTrue();
    expect(DB::table('auth_recovery_proofs')->where('identifier_value', 'aaa-100@acme.example')->exists())->toBeTrue();
    expect(DB::table('auth_identifier_verifications')->where('identifier_value', 'aaa-100@acme.example')->exists())->toBeTrue();

    /*
     * A value rewrite is any update ASSIGNING a value column, wherever in the SET clause it
     * appears. Counting them is the control: a matcher recognising none leaves every
     * assertion below vacuous, which is how `set id = id, value = …` passed.
     */
    $valueRewrites = array_values(array_filter($statements, static function (array $statement): bool {
        $sql = strtolower($statement['sql']);

        return str_starts_with(ltrim($sql), 'update')
            && (str_contains($sql, 'value" =') || str_contains($sql, 'value` ='));
    }));

    expect(count($valueRewrites))->toBeGreaterThan(3);

    /*
     * The SQL-text predicate check that used to live here is GONE, and why belongs in the
     * file because it cost three rounds of review to learn.
     *
     * It tried to establish "the lookup is index-served" by reading the statement, and every
     * version of it rejected correct SQL. Demanding `type = ? and value in (…)` rejected the
     * same statement with its conjuncts reversed. Banning OR rejected a batched
     * `(type = ? AND value IN (…)) OR (type = ? AND value IN (…))`, which plans as
     * MULTI-INDEX OR with both columns on every branch. Splitting on OR and requiring each
     * branch to be complete then rejected `(type = ? OR type = ?) AND value IN (…)`, where
     * the value constraint is shared rather than per branch.
     *
     * Each of those is a different spelling of the same correct thing, and the test was
     * prescribing a spelling. The property is what the PLANNER does with the statement, so
     * that is what is asserted, and only on the engine whose plan this can read.
     */
    if (DB::connection()->getDriverName() !== 'sqlite') {
        return;
    }

    /*
     * And the engine agrees, positively rather than by the absence of a word: every access
     * path the statement uses to reach its TARGET must name the two-column lookup, which is
     * what separates an index seek on (type, value) from a scan of one type's rows.
     *
     * Asserting the absence of `SCAN` instead was satisfied by `where +value in (…) and
     * "type" = ?`, which SQLite plans as `SEARCH … (type=?)` -- every row of the type, per
     * chunk.
     */
    $plans = [];

    foreach ($valueRewrites as $statement) {
        $plan = planDetails($statement);
        $target = planUpdateTarget($statement['sql']);

        if ($target === null) {
            $plans[] = $statement['sql'] . ' (its update target is not one of the upgrade\'s tables)';

            continue;
        }

        [$typeColumn, $valueColumn] = UPGRADE_TABLES[$target['table']];
        $wanted = [$typeColumn . '=? AND ' . $valueColumn . '=?'];
        $access = planTargetAccess($plan, $target['names']);

        $unreadable = array_filter(
            $plan,
            static fn (array $step): bool => $step['detail'] === UNREADABLE_PLAN_STEP,
        );

        if ($unreadable !== [] || $access === []) {
            $plans[] = $statement['sql'] . ' (no readable target access path)';

            continue;
        }

        /*
         * EVERY target access path, not any step of the plan. Measured: an update whose
         * target full-scanned while a nested subquery did the indexed lookup satisfied an
         * any-step match -- `SCAN auth_recovery_proofs` at the top with
         * `LIST SUBQUERY / SEARCH … (identifier_type=? AND identifier_value=?)` beneath it --
         * and passed the whole file. A lookup inside a subquery says nothing about how the
         * UPDATE reaches the rows it writes.
         */
        foreach ($access as $path) {
            $matched = array_filter(
                $wanted,
                static fn (string $lookup): bool => str_contains($path, $lookup),
            );

            if ($matched === []) {
                $plans[] = $path . ' (wanted one of: ' . implode(', ', $wanted) . ')';
            }
        }
    }

    expect($plans)->toBe([]);

    /*
     * The scan budget that used to live here is GONE, and the reason belongs in the file.
     *
     * It tried to establish an asymptotic property from plan shapes on one small run, and
     * three successive reviews found a P1 in it: a bounded intermediate (`select * from (…)
     * as page`) counted as a source scan and rejected a correct implementation; a
     * bracket-quoted alias (`[t]`) hid a genuine per-page scan from it; and -- decisively --
     * a repeated full traversal written as `where id > 0` reports `SEARCH t USING INTEGER
     * PRIMARY KEY (rowid>?)`, which no scan-shape rule can see. Two of those three rejected
     * CORRECT code, which is the worse direction to be wrong in.
     *
     * So the asymptotic claim sits where it can be measured rather than inferred: in
     * 'it rewrites a whole table in time that grows no worse than the table', which samples
     * three sizes and bounds each doubling. What stays here is the target-lookup check, under
     * the scope this case opens with -- a regression guard on the shipped implementation
     * rather than a verifier of every correct one.
     */
});

it('is given a memory limit that actually bites', function (): void {
    /*
     * The positive control for the test above, and it is not ceremony: if the limit
     * were not applied -- a php.ini that forbids overriding it, a wrapper that
     * rewrites the flag -- then "the upgrade completed under 16M" would pass on a
     * process with no limit at all, and the guard would be inert exactly when it
     * mattered.
     */
    $result = phpUnderMemoryLimit(
        '16M',
        dirname(__DIR__) . '/Fixtures/identifier-upgrade-scan.php',
        dirname(__DIR__, 2),
        '0',
        'control',
    );

    expect($result['status'])->not->toBe(0);
    expect($result['errors'] . $result['output'])->toContain('Allowed memory size');
});

/*
 * #89, #90, #91. Four defects a second review found in the bounded scan after a
 * first review had passed it, each reproduced against the real schema.
 *
 * They share a cause worth naming: the scan stopped reading rows directly and
 * started reading them through a working table, and three assumptions came with
 * that which nothing pinned -- that every row is reachable by paging on the primary
 * key, that a value copied into the working table means what it meant in the source
 * column, and that the session which wrote the working table is the session that
 * reads it.
 */

it('refuses over a component whose terminal row is outside the paging range', function (int $id): void {
    if (DB::connection()->getDriverName() === 'mysql') {
        $this->markTestSkipped('MySQL rewrites an explicit zero key and rejects a negative one on an unsigned column.');
    }

    revertToLegacyCollation();

    /*
     * The scan pages with `where id > ?` from a cursor of zero, so a row at or below
     * zero is never read -- and a component whose only TERMINAL member is that row
     * looks live, which under the transient policy deletes it instead of refusing.
     * An imported or restored table is where such a key comes from.
     *
     * Both zero AND a negative, because they are different bugs: measured, moving the
     * cursor to -1 fixes the zero case and leaves a proof at -5 silently deleted.
     * PostgreSQL stores both verbatim -- `bigserial` and `GENERATED BY DEFAULT AS
     * IDENTITY` accept explicit values -- so only MySQL hides this.
     */
    DB::table('auth_recovery_proofs')->insert([
        'id' => $id,
        'identifier_type' => 'email',
        'identifier_value' => 'Ada@Acme.Example',
        'code_hash' => 'hash-' . $id,
        'is_decoy' => false,
        'attempts' => 0,
        'expires_at' => now()->addMinutes(5),
        'consumed_at' => (string) now(),
        'created_at' => (string) now(),
        'updated_at' => (string) now(),
    ]);
    $live = rawProof('ada@acme.example');

    // The premise: the row really is at the id asked for, so what follows is about
    // the cursor rather than about a fixture that failed to place it.
    expect(DB::table('auth_recovery_proofs')->where('id', $id)->exists())->toBeTrue();

    $refused = refusedIds();
    sort($refused);
    $expected = [$id, $live];
    sort($expected);

    expect($refused)->toBe($expected);
    // And nothing was deleted while the refusal was being missed.
    expect(DB::table('auth_recovery_proofs')->count())->toBe(2);
})->with([
    'a zero key' => [0],
    'a negative key' => [-5],
]);

it('treats a zero terminal timestamp as terminal', function (): void {
    if (DB::connection()->getDriverName() !== 'sqlite') {
        $this->markTestSkipped('Only SQLite stores a bare zero in a datetime column; PostgreSQL raises 22008 and MySQL rejects it.');
    }

    revertToLegacyCollation();

    /*
     * `consumed_at = 0` is a real consumed proof: SQL sees a non-null value and the
     * model casts it to 1970-01-01. It reads as NOT terminal, so the proof is deleted
     * rather than refused over. The implementation this replaced asked only whether
     * the column was non-null.
     *
     * Where the misreading happens, stated precisely because the obvious guess is
     * wrong: flag() is applied to the row read from the SOURCE table during fill(),
     * not to the working table's copy -- the working table stores the already-computed
     * 0-or-1 in its own `terminal` column. SQLite hands the source value back as PHP
     * int 0, which flag()'s numeric branch reads as false.
     *
     * And the one-line fix does not work: flag() is shared between these timestamp
     * columns and the working table's boolean `terminal`, so widening it to
     * `$value !== null` makes every terminal row terminal and breaks the delete tests.
     * It needs two helpers -- measured.
     */
    $consumed = DB::table('auth_recovery_proofs')->insertGetId([
        'identifier_type' => 'email',
        'identifier_value' => 'Ada@Acme.Example',
        'code_hash' => 'hash-epoch',
        'is_decoy' => false,
        'attempts' => 0,
        'expires_at' => now()->addMinutes(5),
        'consumed_at' => 0,
        'created_at' => (string) now(),
        'updated_at' => (string) now(),
    ]);
    $live = rawProof('ada@acme.example');

    // The premise: stored and non-null, which is what makes it terminal.
    expect(DB::table('auth_recovery_proofs')->where('id', $consumed)->whereNotNull('consumed_at')->exists())
        ->toBeTrue();

    expect(refusedIds())->toBe([$consumed, $live]);
    expect(DB::table('auth_recovery_proofs')->count())->toBe(2);
});

it('leaves a caller transaction for the caller to roll back', function (): void {
    revertToLegacyCollation(except: ['auth_identifiers']);
    rawIdentifier('Ada@Acme.Example', 1);
    rawIdentifier('ada@acme.example', 2);

    /*
     * The working table is created and dropped with DDL, and on MySQL a plain
     * `DROP TABLE` implicitly commits -- the TEMPORARY keyword is what exempts it. So
     * an upgrade run inside a caller's transaction committed that transaction, and
     * Laravel went on reporting level 1, so nothing in the framework noticed.
     *
     * Three assertions, because two earlier versions of this test proved less than the
     * name claims. Measured: deleting the marker insert made it PASS on MySQL, since
     * its whole signal rested on a precondition it never checked; and a mutant that
     * ROLLED THE CALLER'S TRANSACTION BACK itself also passed, because rollBack() at
     * level zero is a silent no-op. So the marker's presence is asserted first, the
     * transaction depth is asserted after the upgrade returns, and only then is the
     * rollback's effect checked.
     */
    DB::beginTransaction();

    DB::table('auth_policies')->insert([
        'scope' => 'login',
        'document' => '{"all_of":[]}',
        'created_at' => (string) now(),
        'updated_at' => (string) now(),
    ]);

    // Written, and inside the transaction.
    expect(DB::table('auth_policies')->count())->toBe(1);
    expect(DB::transactionLevel())->toBe(1);

    try {
        runIdentifierMigration();
    } catch (Throwable) {
        /*
         * Any throwable, not just a refusal. Refusing to RUN inside an open
         * transaction is one of the two sanctioned fixes for this defect, and a
         * narrower catch rejected it -- the test died before reaching its own
         * rollback and leaked the transaction into teardown.
         */
    }

    // The caller's transaction is still the caller's.
    expect(DB::transactionLevel())->toBe(1);

    DB::rollBack();

    expect(DB::table('auth_policies')->count())->toBe(0);
});

it('works through a connection whose reads and writes are separate sessions', function (string $shape): void {
    revertToLegacyCollation();

    /*
     * A temporary table belongs to the session that created it. The working table is
     * written through the WRITE pdo -- statement() and insert() both use it -- and
     * read back with Connection::select(), whose $useReadPdo defaults to true. On any
     * connection with a read/write split those are different sessions.
     *
     * TWO shapes, because there are three reads and a fixture without a collision
     * reaches only two of them. An earlier version seeded one already-canonical row:
     * measured, the candidate read-back never executed, so a fix that switched two of
     * the three calls passed while the defect survived at the third.
     */
    match ($shape) {
        'a collision it must report' => (function (): void {
            rawProof('Ada@Acme.Example', consumedAt: (string) now());
            rawProof('ada@acme.example', consumedAt: (string) now());
        })(),
        'a row it must rewrite' => (function (): void {
            rawIdentifier('Ada@Acme.Example', 1);
        })(),
        default => throw new InvalidArgumentException('Unknown split shape "' . $shape . '".'),
    };

    $name = stringValue(DB::getDefaultConnection());
    $config = config('database.connections.' . $name);

    if (! is_array($config)) {
        throw new RuntimeException('The default connection has no configuration to split.');
    }

    Config::set('database.connections.vouch_split', array_merge($config, [
        'read' => [],
        'write' => [],
        // Sticky would send reads to the writer after the first write and hide this.
        'sticky' => false,
    ]));

    DB::purge('vouch_split');
    $split = DB::connection('vouch_split');

    // The premise: the two halves really are distinct pdo objects, or this is the
    // ordinary single-session path under another name.
    expect($split->getReadPdo())->not->toBe($split->getPdo());

    $upgrade = new IdentifierEqualityUpgrade($split, app(IdentifierCanonicalizer::class));

    if ($shape === 'a collision it must report') {
        // The refusal has to travel back through the split, which is the only route
        // that reaches the candidate read.
        expect(fn (): null => $upgrade->apply())->toThrow(IdentifierCollisionsFound::class);

        return;
    }

    $upgrade->apply();

    // Rewritten, not merely present: the earlier assertion used an already-canonical
    // value and so held before apply() was ever called.
    expect(DB::table('auth_identifiers')->where('value', 'ada@acme.example')->exists())->toBeTrue();
    expect(DB::table('auth_identifiers')->where('value', 'Ada@Acme.Example')->exists())->toBeFalse();
})->with([
    'a collision it must report',
    'a row it must rewrite',
]);

it('leaves no working table behind after a successful run', function (): void {
    /*
     * By NAME, because the coverage was entirely incidental: the next run's
     * `create temporary table` collides with a leftover, so a scan that never drops
     * fails almost every test in this file for a reason that names nothing. Measured,
     * that is real coverage -- but it does not see a driver-conditional
     * `drop temporary table` leaving a PERMANENT table of the same name behind, which
     * MySQL warns about rather than refusing.
     */
    revertToLegacyCollation();
    rawIdentifier('Ada@Acme.Example', 1);

    runIdentifierMigration();

    // The premise: it really did the work, so the absence below is a drop rather than
    // a run that stopped early.
    expect(DB::table('auth_identifiers')->where('value', 'ada@acme.example')->exists())->toBeTrue();

    expect(tableNames())->not->toContain('vouch_identifier_upgrade_scan');
});

/** Non-canonical filler: every row distinct, and every row needing a rewrite. */
function uppercaseFiller(int $count, int $firstUserId): void
{
    $now = (string) now();

    foreach (array_chunk(range(0, $count - 1), 250) as $batch) {
        $rows = [];

        foreach ($batch as $offset) {
            /*
             * Three types, cycled, two of them needing canonicalization themselves. A
             * single-type filler admitted a rewrite that qualified every value update by
             * the FIRST ROW's type: measured, it rewrote every email row and no username
             * row while passing the whole file on all three engines.
             */
            $types = ['email', 'EMAIL', 'Username'];

            $rows[] = [
                'user_id' => $firstUserId + $offset,
                'type' => $types[$offset % count($types)],
                'value' => sprintf('AAA-%d@ACME.EXAMPLE', $firstUserId + $offset),
                'verified_at' => $now,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        DB::table('auth_identifiers')->insert($rows);
    }
}

it('keeps its statement count bounded when the large table needs rewriting', function (): void {
    /*
     * The companion to the memory bound, and the reason it is a separate case: the
     * existing ceiling is measured on filler that is already CANONICAL, so it bounds
     * the scan and never touches the rewrite at all. Trading the accumulated pairs
     * for chunked reads buys bounded memory WITH statements, and nothing in the file
     * stopped it spending them one pair at a time.
     *
     * Twelve hundred rows, all distinct and none canonical, so a per-pair
     * implementation costs at least twelve hundred statements.
     *
     * The ceiling is derived from measurements rather than chosen, and the arithmetic
     * is stated because a first version of this comment double-counted the updates
     * the accumulating rewrite already performs.
     *
     * Measured totals for the accumulating rewrite, including this test's own four
     * assertion queries: 39 on SQLite, 42 on MySQL and PostgreSQL; the migration
     * alone is 35 / 38 / 38. A streamed rewrite REPLACES its six existing chunked
     * updates with a read and an update per pair-chunk, so at a chunk of 25 it costs
     * roughly 129 / 132 / 132 before any bookkeeping -- which is why the ceiling is
     * 150 and not 120. It admits a pair-chunk down to about 22 and rejects a per-pair
     * implementation by 8x: one built that way spent 1 233 statements.
     *
     * The existing canonical-filler bound next door is 120 on the same row count and
     * bounds a different thing: it never rewrites anything at all.
     */
    revertToLegacyCollation();
    uppercaseFiller(1200, 100);

    $queries = 0;
    DB::listen(function () use (&$queries): void {
        $queries++;
    });

    runIdentifierMigration();

    // The control: a listener that never fired, or an up() that did nothing, would
    // satisfy any ceiling.
    expect($queries)->toBeGreaterThan(0);
    // And the work really happened, which is what makes the ceiling a bound on
    // rewriting rather than on refusing.
    expect(DB::table('auth_identifiers')->count())->toBe(1200);
    expect(DB::table('auth_identifiers')->where('value', 'aaa-100@acme.example')->exists())->toBeTrue();
    expect(DB::table('auth_identifiers')->where('value', 'AAA-100@ACME.EXAMPLE')->exists())->toBeFalse();
    /*
     * EVERY row against its OWN expected value, compared in PHP so the predicate is
     * the same on all three engines -- SQLite and PostgreSQL concatenate with `||`
     * where MySQL reads it as OR.
     *
     * Two things this catches that a canonical-looking count does not. A streamed
     * rewrite that lost one chunk of pairs leaves a contiguous run untouched, which a
     * spot check passes. And a mutant that rotated targets within each batch left
     * every row lower-case with 1 194 of 1 200 belonging to the wrong subject, which
     * a shape-only predicate passed at 39 statements.
     */
    $expected = [];
    $types = ['email', 'EMAIL', 'Username'];

    for ($userId = 100; $userId < 1300; $userId++) {
        // The canonical TYPE as well, since the filler carries three and two of them need
        // rewriting: a value correct under the wrong type is still the wrong row.
        $expected[] = $userId . ' ' . strtolower($types[($userId - 100) % count($types)])
            . ' ' . sprintf('aaa-%d@acme.example', $userId);
    }

    /*
     * The whole (owner, value) set, compared as one list rather than row by row with a
     * filter. Two mutants passed the filtered version: setting every owner to 0 made
     * `where user_id >= 100` exclude every row, so nothing was counted; and a
     * non-numeric owner fell through an is_numeric fallback onto a sentinel that its
     * corrupted value happened to match. Comparing the set has no predicate to slip
     * past -- a changed owner, a changed value, a lost row and a duplicated one are
     * all simply a different list.
     */
    $actual = DB::table('auth_identifiers')
        ->orderBy('id')
        ->get(['user_id', 'type', 'value'])
        ->map(static fn (object $row): string => stringValue($row->user_id)
            . ' ' . stringValue($row->type)
            . ' ' . stringValue($row->value))
        ->all();

    sort($actual);
    sort($expected);

    expect($actual)->toBe($expected);

    expect($queries)->toBeLessThan(150);
});
