<?php

declare(strict_types=1);

use Fissible\Vouch\Identifiers\IdentifierCollisionsFound;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

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
    rawProof('Ada@Acme.Example', consumedAt: (string) now());
    rawProof('ada@acme.example');

    /*
     * A consumed proof is the record of a redemption, and a burned one of an
     * exhausted guessing budget. Both are permanent by decision elsewhere, so
     * the mixed case refuses rather than quietly rewriting history.
     */
    expect(fn (): null => runIdentifierMigration())->toThrow(IdentifierCollisionsFound::class);
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
                'value' => sprintf('filler-%d@acme.example', $firstUserId + $offset),
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

    /*
     * The premise: the two really are far apart in id order, so any chunking
     * smaller than the gap must reach across it to see them as one group.
     */
    expect($second - $first)->toBeGreaterThan(STRADDLE_GAP);

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

it('closes a group it can only reach by following both relations across chunks', function (): void {
    if (DB::connection()->getDriverName() !== 'mysql') {
        $this->markTestSkipped('Only an accent-insensitive collation makes two spellings one address.');
    }

    revertToLegacyCollation();

    /*
     * Three rows, one group, and no single relation joins all three:
     *
     *   FIRST and SECOND share a canonical form  (Jose@... lowercases onto jose@...)
     *   SECOND and THIRD share a loose class     (jose@... and josé@... under ai_ci)
     *
     * So FIRST reaches THIRD only by going canonical, then loose. A chunked scan
     * that closes within a chunk and then merges results by either key alone
     * splits this into two groups and reports the wrong rows; one that drops the
     * closure entirely reports nothing at all. Each row is a full gap from the
     * next, so no two of them can share a chunk.
     */
    $first = rawProof('Jose@acme.example', consumedAt: (string) now());
    straddleProofFiller(STRADDLE_GAP, 1000);
    $second = rawProof('jose@acme.example', consumedAt: (string) now());
    straddleProofFiller(STRADDLE_GAP, 5000);
    $third = rawProof("jos\u{e9}@acme.example", consumedAt: (string) now());

    expect($second - $first)->toBeGreaterThan(STRADDLE_GAP);
    expect($third - $second)->toBeGreaterThan(STRADDLE_GAP);

    expect(refusedIds())->toBe([$first, $second, $third]);
});

it('keeps its statement count bounded when the table is large', function (): void {
    /*
     * A chunked scan buys bounded memory with statements, and nothing else stops
     * it spending them a row at a time. The existing bound in this file is
     * measured on forty rows, where a chunk of one is invisible; this one seeds
     * enough that a degenerate chunk costs thousands of statements.
     *
     * Deliberately the same ceiling as the pairwise-detection test, because the
     * claim is the same: the work is set-based, and a larger table does not buy
     * proportionally more statements.
     */
    revertToLegacyCollation();
    straddleFiller(STRADDLE_GAP, 100);

    $queries = 0;
    DB::listen(function () use (&$queries): void {
        $queries++;
    });

    runIdentifierMigration();

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
     * Ten thousand rather than the hundred thousand a real host has: the slope is
     * linear, so the smallest count that clears the limit by a comfortable margin
     * proves the same thing and costs the suite four seconds instead of a minute.
     */
    $result = phpUnderMemoryLimit(
        '16M',
        dirname(__DIR__) . '/Fixtures/identifier-upgrade-scan.php',
        dirname(__DIR__, 2),
        '10000',
    );

    expect($result['status'])->toBe(0, 'the upgrade must complete under a limit the old scan exhausted');
    // The surviving row count, so an upgrade that "succeeded" by emptying the table
    // or by refusing without working is a different answer rather than the same one.
    expect(trim($result['output']))->toBe('10000');
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
