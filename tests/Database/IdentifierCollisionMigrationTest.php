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
    expect(indexExists('auth_identifiers', 'auth_identifiers_type_value_unique'))->toBeTrue()
        ->and(indexExists('auth_proof_issuance_locks', 'auth_proof_issuance_locks_scope_unique'))
        ->toBeTrue();

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

it('canonicalizes the issuance lock rows too', function (): void {
    revertToLegacyCollation();

    DB::table('auth_proof_issuance_locks')->insert([
        'ceremony' => 'recovery',
        'identifier_type' => 'email',
        'identifier_value' => "JOS\u{c9}@ACME.EXAMPLE",
    ]);

    /*
     * The fourth table in scope, and the one nothing read. Two spellings of one
     * address would otherwise each hold their own serialization anchor, which is
     * precisely what that table exists to prevent.
     *
     * A trap for whoever writes the rewrite: do NOT probe for an existing
     * canonical twin with where(value, $canonical) before updating. Under the
     * collation being replaced that query is answered by the row you are about
     * to rewrite -- JOSE-with-acute IS jose to utf8mb4_0900_ai_ci -- so the
     * probe reports a twin that does not exist and the only anchor gets deleted.
     * Attempt the write and handle the constraint violation instead.
     */
    runIdentifierMigration();

    expect(DB::table('auth_proof_issuance_locks')->pluck('identifier_value')->all())
        ->toBe([canonical("JOS\u{c9}@ACME.EXAMPLE")]);
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

it('leaves one anchor when two spellings claim the same scope', function (): void {
    /*
     * Constructible only where equality is already byte-exact, which is why the
     * collation is left alone here. Two anchors canonicalizing onto one value
     * cannot both survive: unique(ceremony, type, value) forbids it, so the
     * non-canonical row goes rather than the migration refusing -- a lock row is
     * a mutex, not a record of anything.
     */
    if (DB::connection()->getDriverName() === 'mysql') {
        $this->markTestSkipped('The legacy collation already treats these as one row.');
    }

    DB::table('auth_proof_issuance_locks')->insert([
        ['ceremony' => 'recovery', 'identifier_type' => 'email',
            'identifier_value' => 'Ada@Acme.Example'],
        ['ceremony' => 'recovery', 'identifier_type' => 'email',
            'identifier_value' => 'ada@acme.example'],
    ]);

    runIdentifierMigration();

    expect(DB::table('auth_proof_issuance_locks')
        ->where('identifier_value', 'ada@acme.example')->count())->toBe(1)
        ->and(DB::table('auth_proof_issuance_locks')->count())->toBe(1);
});
