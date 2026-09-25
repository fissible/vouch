<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthRecoveryProof;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Console\RetentionManifest;
use Fissible\Vouch\Support\IssuanceLockBucket;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/*
 * #46. The issuance mutex stops being a record of who asked.
 *
 * #38 needed an anchor to serialize concurrent issuance, because proof rows
 * cannot be one: the first issuance for an identifier has none, and retention
 * eventually deletes the ones that exist. It allocated a row per submitted
 * identifier, keyed on the string the caller sent, before resolution and
 * whether or not resolution succeeded.
 *
 * Two consequences, and the second is the worse one. Any string a caller
 * submits allocates a permanent row, so the table grows with attacker-chosen
 * input and no throttle bounds it -- the per-identifier issuance limits count
 * repetition, and rotating identifiers walks straight past them. And the row
 * stores that string verbatim and forever, so an arbitrary address, including
 * one belonging to somebody who is not a user, is retained with no reclamation
 * path.
 *
 * A mutex does not need to know what it is protecting. Hashing the scope into a
 * fixed set of buckets keeps the serialization and discards the identity, which
 * removes the retention question rather than managing it -- no deletion
 * protocol to prove safe against a concurrent holder, because there is nothing
 * to delete.
 *
 * The cost is false sharing: two unrelated identifiers landing in one bucket
 * serialize against each other for the length of one issuance transaction. That
 * is the trade, and the tests below hold the line that separates it from a
 * bug -- false sharing may cost latency and must never move state between
 * identifiers.
 *
 * The hash is keyed through the same seam as every other binding, so a caller
 * cannot work out which bucket an identifier lands in, let alone aim several at
 * one. Unkeyed, an attacker could concentrate traffic on a single bucket and
 * turn false sharing into a denial of service -- and a key-dependent OFFSET over
 * an unkeyed hash is not enough either, since it moves every bucket while
 * preserving which pairs collide.
 *
 * WHICH INPUTS SHARE A MUTEX IS THE DATABASE'S ANSWER, NOT THIS PACKAGE'S.
 *
 * That took three attempts to get right, and the first two were measured wrong
 * rather than argued wrong. Folding accents left MySQL equating strasse and
 * stra(sharp-s), ae and (ae-ligature), sigma and final sigma, width and
 * soft-hyphen variants that the fold sent to different buckets. Replacing the
 * fold with an ICU primary-strength collation key -- same UCA foundation as
 * utf8mb4_0900_ai_ci -- still split pairs the column equates: MySQL pins UCA
 * 9/CLDR 30 while ICU ships tailored, versioned data, and across sixteen
 * thousand generated pairs twenty diverged. ICU's key bytes also move between
 * ICU releases, so that mapping would shift under a PHP upgrade and two
 * processes mid-rollout would stop serializing the same identifier.
 *
 * So the comparison key comes from the ACTIVE CONNECTION, for the ACTUAL column
 * collation -- the same authority the supersession predicate answers to, which
 * is the only thing that can be right by construction rather than by a list
 * someone has to keep finishing. On engines where identifier equality is binary
 * there is nothing to fold and the key is the string; on MySQL it is the
 * collation's own weights. The consequence worth stating plainly: two spellings
 * that this package would call the same address get different buckets on a
 * case-sensitive engine, and that is CORRECT, because the engine gives them
 * different proof scopes too.
 *
 * Rotating the keying secret moves every bucket at once, so it needs a
 * coordinated deployment or a dual-lock transition: mid-rotation, old and new
 * processes would derive different mutexes for one identifier and stop
 * serializing. That is a release note, not a test.
 */

/*
 * 4,096. With C simultaneous distinct issuances the arriving request shares a
 * bucket with probability about (C-1)/4096, so a deployment seeing ten at once
 * contends roughly one request in 455 -- and contention costs the length of one
 * issuance transaction, not a failure. Four thousand rows of two small columns
 * is nothing to store, and raising it further buys less than it costs to
 * rehash: the number is part of the derivation, so changing it moves every
 * scope's bucket at once.
 */
const EXPECTED_BUCKETS = 4096;

function lockRowCount(): int
{
    return DB::table('auth_proof_issuance_locks')->count();
}

/** Every value stored in the lock table, whatever its columns are called. */
function lockTableContents(): string
{
    $rendered = '';

    foreach (DB::table('auth_proof_issuance_locks')->orderBy('id')->get() as $row) {
        $rendered .= json_encode($row, JSON_THROW_ON_ERROR);
    }

    return $rendered;
}

function verifiedAddress(string $value, int $userId = 1): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

function permitDelivery(): void
{
    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
}

/** Request a recovery proof for a submitted string, throttles cleared first. */
function requestRecoveryFor(string $submitted): void
{
    DB::table('auth_throttle_counters')->delete();
    DB::table('auth_throttle_tuples')->delete();

    app(CredentialRecovery::class)->request(new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $submitted,
        tenantId: null,
        clientIp: '203.0.113.10',
    ));
}

function lockProofTable(string $ceremony): string
{
    return $ceremony === 'recovery' ? 'auth_recovery_proofs' : 'auth_identifier_verifications';
}

function lockIssueFor(string $ceremony, string $submitted): void
{
    $ceremony === 'recovery'
        ? requestRecoveryFor($submitted)
        : requestVerificationFor($submitted);
}

function requestVerificationFor(string $submitted): void
{
    DB::table('auth_throttle_counters')->delete();
    DB::table('auth_throttle_tuples')->delete();

    app(IdentifierVerifier::class)->request(new IdentifierVerificationRequest(
        type: 'email',
        submittedIdentifier: $submitted,
        tenantId: null,
        clientIp: '203.0.113.10',
    ));
}

it('seeds a fixed number of buckets and never allocates another', function (): void {
    permitDelivery();
    $before = lockRowCount();

    for ($i = 0; $i < 60; $i++) {
        requestRecoveryFor(sprintf('nobody-%d@acme.example', $i));
    }

    /*
     * Sixty distinct submitted strings, none of them a real identifier. The
     * count must not move at all: the buckets exist from the migration, and
     * issuance takes one rather than creating one.
     */
    expect($before)->toBe(EXPECTED_BUCKETS)
        ->and(lockRowCount())->toBe(EXPECTED_BUCKETS);
});

it('keeps the submitted identifier out of the lock table', function (): void {
    permitDelivery();

    $submitted = 'traceable-address@acme.example';
    requestRecoveryFor($submitted);

    /*
     * The whole table, not a named column: the point is that the string is not
     * retained anywhere, and a schema that renamed the column while still
     * storing it would satisfy a column-shaped assertion.
     */
    expect(lockTableContents())->not->toContain($submitted)
        ->and(lockTableContents())->not->toContain('traceable-address')
        ->and(Schema::hasColumn('auth_proof_issuance_locks', 'identifier_value'))->toBeFalse();
});

it('sends one string to one bucket', function (): void {
    /*
     * Stability only. An earlier version asserted that case and whitespace
     * variants shared a bucket, which the change of authority makes WRONG on
     * SQLite and PostgreSQL: there the column separates them, so they have
     * separate proof scopes and must not be forced to contend. What inputs are
     * equivalent is now asked of the column, below.
     */
    $bucket = IssuanceLockBucket::for('recovery', 'email', 'ada@acme.example');

    expect(IssuanceLockBucket::for('recovery', 'email', 'ada@acme.example'))->toBe($bucket);
});

it('does not send every identifier to the same bucket', function (): void {
    /*
     * The paired negative, and it is not hypothetical: a derivation that
     * returned a constant would bound the row count perfectly, keep every
     * identifier out of the table, and serialize the entire application behind
     * one row.
     */
    $buckets = [];

    for ($i = 0; $i < 200; $i++) {
        $buckets[] = IssuanceLockBucket::for('recovery', 'email', sprintf('user-%d@acme.example', $i));
    }

    expect(count(array_unique($buckets)))->toBeGreaterThan(100);
});

it('separates the two ceremonies within one bucket space', function (): void {
    // The ceremony is part of the scope, as it was before: recovery and
    // verification for one address are different issuances and need not block
    // each other.
    $differ = 0;

    for ($i = 0; $i < 100; $i++) {
        $address = sprintf('ceremony-%d@acme.example', $i);

        if (IssuanceLockBucket::for('verification', 'email', $address)
            !== IssuanceLockBucket::for('recovery', 'email', $address)) {
            $differ++;
        }
    }

    /*
     * Across a sample, not on one address: two ceremonies that agreed for
     * exactly one input would satisfy a single inequality while mapping every
     * other scope together. They collide sometimes -- one bucket space, by
     * design -- so this asks that they mostly do not.
     */
    expect($differ)->toBeGreaterThan(90);
});

/**
 * The bucket for each of a fixed set of addresses, under the current key.
 *
 * @return list<int>
 */
function bucketVector(string $ceremony = 'recovery'): array
{
    $vector = [];

    for ($i = 0; $i < 60; $i++) {
        $vector[] = IssuanceLockBucket::for($ceremony, 'email', sprintf('vector-%d@acme.example', $i));
    }

    return $vector;
}

/**
 * Rotate whatever secret keys the derivation.
 *
 * Both are moved, deliberately. The owner called for a dedicated bucket secret;
 * a domain-separated derivation from APP_KEY would satisfy that too, and this
 * test has no business choosing. Rotating both means the assertion holds for
 * either construction -- an earlier version rotated only app.key and failed a
 * correct implementation that used a dedicated one.
 */
function rotateBucketSecret(string $seed): void
{
    $value = 'base64:' . base64_encode(str_repeat($seed, 32));

    Config::set('app.key', $value);
    Config::set('vouch.issuance_locks.secret', $value);
}

it('derives buckets that a caller cannot predict', function (): void {
    $first = bucketVector();

    rotateBucketSecret('k');
    $second = bucketVector();

    /*
     * A VECTOR, not one address. A legitimate keyed construction can leave any
     * single address on the same bucket under two keys -- one chance in 4,096,
     * and a measured HMAC variant did exactly that -- so asserting one address
     * moves would fail correct work about once in every few thousand runs.
     * Asking that most of sixty move cannot.
     */
    $moved = 0;

    foreach ($first as $i => $bucket) {
        if ($second[$i] !== $bucket) {
            $moved++;
        }
    }

    expect($moved)->toBeGreaterThan(50);
});

it('does not let a collision found under one key survive another', function (): void {
    [$left, $right] = collidingPair();

    rotateBucketSecret('m');
    $underSecond = IssuanceLockBucket::for('recovery', 'email', $left)
        === IssuanceLockBucket::for('recovery', 'email', $right);

    rotateBucketSecret('n');
    $underThird = IssuanceLockBucket::for('recovery', 'email', $left)
        === IssuanceLockBucket::for('recovery', 'email', $right);

    /*
     * Key dependence alone does not make collisions unpredictable. A
     * construction that hashes the identifier UNKEYED and then adds a
     * key-dependent OFFSET moves every bucket when the key changes while
     * preserving which pairs collide -- so an attacker who finds a colliding
     * pair once keeps it forever, without knowing any key. That mutant passed
     * the test above; this is the one that catches it.
     */
    expect($underSecond && $underThird)->toBeFalse();
});

it('agrees on every mapping across fresh processes', function (): void {
    $fixture = dirname(__DIR__) . '/Fixtures/issuance-lock-mapping.php';
    $key = 'base64:' . base64_encode(str_repeat('s', 32));

    /*
     * The live connection configuration is handed over, because the comparison
     * key comes from the database now. A fixture with only a config repository
     * cannot derive anything and failed a correct implementation.
     */
    $connection = json_encode(
        Config::array('database.connections.' . Config::string('database.default')),
        JSON_THROW_ON_ERROR,
    );

    /*
     * Three genuinely separate interpreters, identical configuration. A
     * derivation that mixed in a per-process random secret is perfectly stable
     * inside one request and passed every other test here -- and two workers
     * handling concurrent issuance for one identifier would then take different
     * mutexes and not serialize at all.
     *
     * A fork cannot show this: it inherits an initialised seed. So this shells
     * out, and asserts the run SUCCEEDED before comparing, because a fixture
     * that failed to boot would otherwise compare three empty outputs and pass.
     */
    $vectors = [];

    for ($run = 0; $run < 3; $run++) {
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open(
            [PHP_BINARY, $fixture, dirname(__DIR__, 2), $key, $connection],
            $descriptors,
            $pipes,
        );

        if (! is_resource($process)) {
            throw new RuntimeException('Could not start a fresh interpreter.');
        }

        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $status = proc_close($process);

        expect($status)->toBe(0, 'The mapping fixture failed: ' . (string) $errors);

        $decoded = json_decode((string) $output, true, 512, JSON_THROW_ON_ERROR);

        if (! is_array($decoded)) {
            throw new RuntimeException('The mapping fixture did not print a list.');
        }

        $vector = $decoded;

        expect($vector)->toHaveCount(40);

        foreach ($vector as $bucket) {
            expect($bucket)->toBeInt()
                ->toBeGreaterThanOrEqual(0)
                ->toBeLessThan(EXPECTED_BUCKETS);
        }

        $vectors[] = $vector;
    }

    expect($vectors[1])->toBe($vectors[0])
        ->and($vectors[2])->toBe($vectors[0]);
});

it('derives a bucket inside the seeded range, stably', function (): void {
    /*
     * Range and stability, not arithmetic. An earlier version of this test
     * reproduced the derivation -- take eight hex digits, modulo the count --
     * which would have forced one construction and rejected every equivalent
     * one. What matters is that the answer addresses a seeded bucket and does
     * not move between calls; HOW it gets there is the implementer's.
     */
    $seen = [];

    for ($i = 0; $i < 200; $i++) {
        $bucket = IssuanceLockBucket::for('recovery', 'email', sprintf('range-%d@acme.example', $i));

        expect($bucket)->toBeGreaterThanOrEqual(0)
            ->and($bucket)->toBeLessThan(EXPECTED_BUCKETS);

        $seen[] = $bucket;
    }

    // Stable across calls: a derivation seeded per-process would serialize
    // correctly within one request and not at all across two.
    foreach ($seen as $i => $bucket) {
        expect(IssuanceLockBucket::for('recovery', 'email', sprintf('range-%d@acme.example', $i)))
            ->toBe($bucket);
    }
});

/**
 * Any two distinct addresses that share a bucket.
 *
 * Searching for a pair rather than for a collision with one fixed target: the
 * latter is a coupon-collector problem and flakes. Against 4,096 buckets,
 * probing 4,000 candidates for a partner to one specific address succeeds only
 * about three times in five, so a test built that way fails for no reason two
 * runs in five. A pair among a few hundred samples is a birthday problem and is
 * effectively certain.
 *
 * @return array{string, string}
 */
function collidingPair(string $ceremony = 'recovery'): array
{
    $seen = [];

    for ($i = 0; $i < 3000; $i++) {
        $candidate = sprintf('probe-%d@acme.example', $i);
        $bucket = IssuanceLockBucket::for($ceremony, 'email', $candidate);

        if (isset($seen[$bucket])) {
            return [$seen[$bucket], $candidate];
        }

        $seen[$bucket] = $candidate;
    }

    throw new RuntimeException('No two probed identifiers shared a bucket.');
}

it('supersedes independently for two identifiers sharing a bucket', function (string $ceremony): void {
    permitDelivery();
    [$first, $second] = collidingPair($ceremony);

    verifiedAddress($first, 1);
    verifiedAddress($second, 2);

    /*
     * The line that separates the trade from a bug. Two addresses in one bucket
     * must contend and nothing else: issuing for one must not supersede,
     * consume or otherwise touch the other's proof.
     *
     * BOTH proofs are required to exist, which the first version of this test
     * omitted -- an implementation that refused issuance whenever a live proof
     * occupied the bucket passed it, because the assertion only looked at the
     * first proof and never noticed the second was missing.
     */
    lockIssueFor($ceremony, $first);
    lockIssueFor($ceremony, $second);

    $table = lockProofTable($ceremony);

    // BOTH rows required: an implementation refusing issuance whenever a live
    // proof occupied the bucket passed while the second was simply missing.
    $firstRow = requiredRow(DB::table($table)->where('identifier_value', $first)->first());
    $secondRow = requiredRow(DB::table($table)->where('identifier_value', $second)->first());

    expect($firstRow->superseded_at)->toBeNull()
        ->and($firstRow->consumed_at)->toBeNull()
        ->and($secondRow->superseded_at)->toBeNull()
        ->and($secondRow->consumed_at)->toBeNull();
})->with(['recovery', 'verification']);

it('supersedes within one identifier even when a neighbour shares its bucket', function (string $ceremony): void {
    permitDelivery();
    [$first, $second] = collidingPair($ceremony);

    verifiedAddress($first, 1);
    verifiedAddress($second, 2);

    /*
     * The other half: sharing a bucket must not WEAKEN supersession either.
     * #38's invariant is that issuing again permanently invalidates the prior
     * proof for that scope, and a neighbour in the mutex changes nothing about
     * it.
     */
    lockIssueFor($ceremony, $first);
    lockIssueFor($ceremony, $second);
    lockIssueFor($ceremony, $first);

    $table = lockProofTable($ceremony);

    /*
     * A live REPLACEMENT and a still-live neighbour, not just counts. Counting
     * one superseded row leaves open whether anything replaced it, and counting
     * zero for the neighbour leaves open whether it exists at all.
     */
    expect(DB::table($table)->where('identifier_value', $first)
        ->whereNotNull('superseded_at')->count())->toBe(1)
        ->and(DB::table($table)->where('identifier_value', $first)
            ->whereNull('superseded_at')->whereNull('consumed_at')->count())->toBe(1)
        /*
         * The neighbour whole, not just unsuperseded. Consuming it during the
         * replacement survived a superseded_at check, and so would burning or
         * expiring it -- any of which moves state between identifiers that only
         * share a mutex.
         */
        ->and(DB::table($table)->where('identifier_value', $second)
            ->whereNull('superseded_at')->whereNull('consumed_at')
            ->whereNull('burned_at')->count())->toBe(1);
})->with(['recovery', 'verification']);

it('seeds buckets idempotently when the migration runs again', function (): void {
    /*
     * The seeder itself, re-entered. Calling `migrate` proves nothing: it skips
     * migrations already recorded, so an unconditional INSERT passed while
     * doubling the table every time it actually ran. Executing up() again is
     * what a re-run does to the statements inside it -- and with a unique
     * constraint present, an unconditional insert throws here rather than
     * doubling, which is also a failure worth catching.
     */
    $migration = require dirname(__DIR__, 2)
        . '/database/migrations/2026_09_12_000001_add_proof_supersession.php';

    $migration->up();

    expect(lockRowCount())->toBe(EXPECTED_BUCKETS);
});

it('seeds exactly the addressable bucket ids', function (): void {
    $ids = [];

    foreach (DB::table('auth_proof_issuance_locks')->pluck('id') as $id) {
        $ids[] = (int) stringValue($id);
    }

    sort($ids);

    /*
     * The whole set, not a sample. Sampling two hundred derivations never
     * selected bucket zero, so seeding 1..4096 against a 0..4095 derivation
     * survived -- and ensureAndLock would then either create the missing row,
     * which is the growth this removes, or lock nothing at all.
     */
    expect($ids)->toBe(range(0, EXPECTED_BUCKETS - 1));
});

it('locks the derived bucket on both issuance paths', function (string $ceremony): void {
    permitDelivery();
    verifiedAddress('ada@acme.example');

    $locked = [];
    DB::listen(function ($query) use (&$locked): void {
        if (str_contains($query->sql, 'auth_proof_issuance_locks')) {
            $locked[] = $query->bindings;
        }
    });

    /*
     * The helper being correct says nothing about the outbox using it. Three
     * measured implementations passed every other test in this file: one with
     * no lock at all, one locking bucket zero always, and one where
     * verification still used the removed identifier columns -- that last
     * because nothing here called the verification path.
     */
    $ceremony === 'recovery'
        ? requestRecoveryFor('ada@acme.example')
        : requestVerificationFor('ada@acme.example');

    $expected = IssuanceLockBucket::for($ceremony, 'email', 'ada@acme.example');
    $flattened = array_merge(...array_map(static fn (array $b): array => array_values($b), $locked));

    expect($locked)->not->toBe([])
        ->and($flattened)->toContain($expected);
})->with(['recovery', 'verification']);

it('issues successfully through both paths', function (string $ceremony): void {
    permitDelivery();
    verifiedAddress('ada@acme.example');

    // The lock is in the issuance path, so breaking it breaks issuance. Asserting
    // the lock without asserting the outcome would accept a mutex that refuses.
    $ceremony === 'recovery'
        ? requestRecoveryFor('ada@acme.example')
        : requestVerificationFor('ada@acme.example');

    $table = $ceremony === 'recovery' ? 'auth_recovery_proofs' : 'auth_identifier_verifications';

    expect(DB::table($table)->where('identifier_value', 'ada@acme.example')->count())->toBe(1);
})->with(['recovery', 'verification']);

/**
 * Spellings whose equivalence differs by engine and by collation.
 *
 * The last six are the ones that showed accent folding to be insufficient:
 * MySQL's utf8mb4_0900_ai_ci equates all of them, and a fold that handled only
 * accents sent each pair to a different bucket. They are here because UCA
 * primary equivalence has far more classes than anyone enumerates by hand,
 * which is the argument for deriving from a collation key rather than a list.
 *
 * @return list<array{string, string}>
 */
function equivalentSpellings(): array
{
    return [
        ['ada@acme.example', 'ADA@acme.example'],
        ['ada@acme.example', 'Ada@Acme.Example'],
        ["jos\u{e9}@acme.example", "jose\u{301}@acme.example"],
        ["jos\u{e9}@acme.example", 'jose@acme.example'],
        ["stra\u{df}e@acme.example", 'strasse@acme.example'],
        ["\u{e6}on@acme.example", 'aeon@acme.example'],
        ["s\u{f8}ren@acme.example", 'soren@acme.example'],
        ["\u{3c2}igma@acme.example", "\u{3c3}igma@acme.example"],
        ["\u{ff41}da@acme.example", 'ada@acme.example'],
        ["a\u{ad}da@acme.example", 'ada@acme.example'],
        // PAD SPACE: even a binary collation equates a trailing ASCII space,
        // which bare comparison weights do not -- measured, and the reason the
        // key needs the engine's own padding treatment rather than raw weights.
        ['ada@acme.example', 'ada@acme.example '],
        ["ada@acme.example\u{a0}", 'ada@acme.example '],
    ];
}

it('maps together whatever the proof column itself considers equal', function (string $ceremony): void {
    permitDelivery();

    /*
     * Asked of the COLUMN, through the predicate supersession actually uses.
     * An earlier version compared `? = ?`, which follows the connection
     * collation rather than the column's -- changing only MySQL's connection
     * collation to binary produced zero equal pairs while the proof columns
     * still equated them, so the test went quiet exactly where the risk was.
     *
     * It was also vacuous on SQLite and PostgreSQL, where no pair is equal and
     * the loop asserted nothing. Here the count of pairs the engine equates is
     * reported rather than required, and the engine-independent contract is the
     * test above -- this one exists to catch an engine equating something that
     * contract does not cover.
     */
    $equated = 0;
    $probed = 0;

    $table = lockProofTable($ceremony);

    foreach (equivalentSpellings() as [$stored, $candidate]) {
        DB::table($table)->delete();
        lockIssueFor($ceremony, $stored);

        // The premise: this fixture really did store a row to compare against.
        expect(DB::table($table)->count())->toBe(1);
        $probed++;

        $matches = DB::table($table)
            ->where('identifier_type', 'email')
            ->where('identifier_value', $candidate)
            ->exists();

        if (! $matches) {
            continue;
        }

        $equated++;

        expect(IssuanceLockBucket::for($ceremony, 'email', $stored))
            ->toBe(
                IssuanceLockBucket::for($ceremony, 'email', $candidate),
                sprintf('the database equates %s and %s, so they must share a bucket', $stored, $candidate),
            );
    }

    /*
     * Reported rather than required: zero is the correct answer where identifier
     * equality is binary, so demanding a nonzero count would fail SQLite and
     * PostgreSQL. What must not happen is the loop going quiet because the
     * FIXTURE stopped landing -- an earlier version asserted $equated >= 0,
     * which is true of an empty run and of a broken one alike.
     */
    expect($probed)->toBe(count(equivalentSpellings()));
})->with(['recovery', 'verification']);

it('follows the column collation in force, not an assumed one', function (): void {
    if (DB::connection()->getDriverName() !== 'mysql') {
        $this->markTestSkipped('Only MySQL has a collation here that equates more than bytes.');
    }

    permitDelivery();

    $pair = ["jos\u{e9}@acme.example", 'jose@acme.example'];
    $underDefault = [
        IssuanceLockBucket::for('recovery', 'email', $pair[0]),
        IssuanceLockBucket::for('recovery', 'email', $pair[1]),
    ];

    /*
     * Hard-coding utf8mb4_0900_ai_ci would be a substitute for asking, and it
     * would be wrong for any host that configured something else -- the mutex
     * has to track the collation the column actually has, because that is what
     * decides the supersession scope it exists to protect.
     *
     * Switched to a binary collation, the column stops equating these two, and
     * the derivation must stop putting them in one bucket. An implementation
     * reading information_schema follows; one with the collation baked in does
     * not move.
     */
    DB::statement(
        'alter table auth_recovery_proofs modify identifier_value '
        . 'varchar(255) character set utf8mb4 collate utf8mb4_bin not null',
    );

    $underBinary = [
        IssuanceLockBucket::for('recovery', 'email', $pair[0]),
        IssuanceLockBucket::for('recovery', 'email', $pair[1]),
    ];

    /*
     * Sampled, not a single pair. Two genuinely distinct comparison keys land in
     * one bucket about once in four thousand, and a measured secret did exactly
     * that here -- so requiring one pair to separate fails correct work at that
     * rate. What must hold is that the collation change moves the RELATION for
     * most of a sample.
     */
    $sharedUnderDefault = 0;
    $sharedUnderBinary = 0;

    foreach (accentPairs() as [$left, $right]) {
        if (IssuanceLockBucket::for('recovery', 'email', $left)
            === IssuanceLockBucket::for('recovery', 'email', $right)) {
            $sharedUnderBinary++;
        }
    }

    expect($underDefault[0])->toBe($underDefault[1])
        ->and($sharedUnderBinary)->toBeLessThan(count(accentPairs()) / 2);
});

/**
 * Pairs the default MySQL collation equates and a binary one does not.
 *
 * @return list<array{string, string}>
 */
function accentPairs(): array
{
    $pairs = [];

    for ($i = 0; $i < 40; $i++) {
        $pairs[] = [
            sprintf("jos\u{e9}-%d@acme.example", $i),
            sprintf('jose-%d@acme.example', $i),
        ];
    }

    return $pairs;
}

it('refuses to derive a bucket it cannot ask the database about', function (): void {
    /*
     * Fail closed. If the connection cannot produce a comparison key -- an
     * engine nobody wrote the expression for -- the only safe answer is to
     * refuse, the way DatabaseTime refuses an interval it cannot express. A
     * fallback to an application-side fold would be exactly the silent
     * under-bucketing this mechanism replaced, arriving on whichever engine
     * nobody tested.
     */
    expect(fn (): int => IssuanceLockBucket::forDriver('nonesuch', 'recovery', 'email', 'ada@acme.example'))
        ->toThrow(InvalidArgumentException::class);
});

it('stores nothing new in the lock table when issuance happens', function (string $ceremony): void {
    permitDelivery();
    verifiedAddress('ada@acme.example');

    $before = lockTableContents();

    $ceremony === 'recovery'
        ? requestRecoveryFor('traceable-address@acme.example')
        : requestVerificationFor('traceable-address@acme.example');

    /*
     * The whole table, byte for byte. Absence of the plaintext is not enough: an
     * implementation storing the identifier base64-encoded in another column
     * passed every substring check. Nothing about this table may change when a
     * caller issues, because the buckets are seeded and the row is only locked.
     */
    expect(lockTableContents())->toBe($before);
})->with(['recovery', 'verification']);

it('records in the retention manifest that no identifier is kept', function (): void {
    /*
     * Read through the accessors, because the entries live in static methods.
     * An earlier version json_encoded the object, which produced "{}" and made
     * the whole assertion vacuous -- it failed only because a positive check hit
     * an empty string, and would have passed had I asserted only the absence.
     */
    $entries = array_merge(
        RetentionManifest::pruned(),
        RetentionManifest::retained(),
        RetentionManifest::unreclaimed(),
    );

    expect($entries)->toHaveKey('auth_proof_issuance_locks');

    $description = $entries['auth_proof_issuance_locks'];

    /*
     * The manifest is the operator's account of what this package keeps
     * forever. Every throwaway implementation measured in review left the old
     * entry in place, still describing capacity that grows with requested
     * identifiers, decoys included -- which this change makes false.
     */
    /*
     * The stale CLAIM, not the word. Banning 'identifier' outright rejected the
     * truthful description "no identifiers are retained", which is the thing
     * this change makes it possible to say.
     */
    expect($description)->not->toContain('grows with distinct requested identifiers')
        ->and($description)->not->toContain('including decoys')
        ->and(RetentionManifest::retained())->toHaveKey('auth_proof_issuance_locks');
});
