<?php

declare(strict_types=1);

use Fissible\Vouch\Support\IpThrottleLockBucket;
use Fissible\Vouch\Support\IssuanceLockBucket;
use Fissible\Vouch\Support\LockBucket;
use Fissible\Vouch\Support\LockBucketSecret;

/*
 * #16. One keyed derivation for every bucketed mutex, one secret, and an
 * overlap window so rotating that secret takes two ordinary deploys.
 */

const LOCK_BUCKET_GOLDEN_SECRET = 'kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk-golden-mapping-secret';

/**
 * The scopes whose #46 buckets were captured from the pre-#16 implementation.
 *
 * @return list<array{string, string, string}>
 */
function lockBucketGoldenScopes(): array
{
    return [
        ['recovery', 'email', 'ada@acme.example'],
        ['verification', 'email', 'ada@acme.example'],
        ['recovery', 'phone', '+15555550100'],
        ['verification', 'email', 'grace@acme.example'],
    ];
}

/** @return list<int> */
function lockBucketGoldenMapping(): array
{
    return array_map(
        static fn (array $scope): int => IssuanceLockBucket::for(...$scope),
        lockBucketGoldenScopes(),
    );
}

function lockBucketSecrets(?string $current, ?string $legacy = null, ?string $previous = null): void
{
    config([
        LockBucketSecret::KEY => $current,
        LockBucketSecret::LEGACY_KEY => $legacy,
        LockBucketSecret::PREVIOUS_KEY => $previous,
    ]);
}

it('keeps the issuance mapping an existing install already uses', function (): void {
    /*
     * Captured from IssuanceLockBucket::for() BEFORE the derivation moved into
     * LockBucket. If upgrading moved any bucket, the upgrade itself would be an
     * uncoordinated rotation: old and new processes would stop serializing.
     */
    lockBucketSecrets(null, LOCK_BUCKET_GOLDEN_SECRET);
    expect(lockBucketGoldenMapping())->toBe([3037, 475, 1651, 3609]);

    lockBucketSecrets(LOCK_BUCKET_GOLDEN_SECRET);
    expect(lockBucketGoldenMapping())->toBe([3037, 475, 1651, 3609]);

    // Positive control: the vector is a function of the secret, so a match
    // above is not a constant the derivation would produce for anything.
    lockBucketSecrets(str_repeat('z', 40));
    expect(lockBucketGoldenMapping())->not->toBe([3037, 475, 1651, 3609]);
});

it('prefers the shared secret over the legacy issuance secret', function (): void {
    $shared = str_repeat('s', 40);
    lockBucketSecrets($shared);
    $underShared = lockBucketGoldenMapping();

    lockBucketSecrets(null, LOCK_BUCKET_GOLDEN_SECRET);
    $underLegacy = lockBucketGoldenMapping();

    expect($underShared)->not->toBe($underLegacy);

    lockBucketSecrets($shared, LOCK_BUCKET_GOLDEN_SECRET);
    expect(LockBucketSecret::current())->toBe($shared)
        ->and(lockBucketGoldenMapping())->toBe($underShared);
});

it('refuses to derive without a secret, naming what to set', function (): void {
    lockBucketSecrets(null);

    expect(fn () => LockBucketSecret::current())
        ->toThrow(RuntimeException::class, 'VOUCH_LOCK_BUCKETS_SECRET');

    lockBucketSecrets('');

    expect(fn () => IssuanceLockBucket::for('recovery', 'email', 'ada@acme.example'))
        ->toThrow(RuntimeException::class, 'VOUCH_LOCK_BUCKETS_SECRET');
});

it('refuses a current secret shorter than 32 bytes', function (): void {
    lockBucketSecrets(str_repeat('a', 31));
    expect(fn () => LockBucketSecret::current())->toThrow(RuntimeException::class, 'too short');

    lockBucketSecrets(null, str_repeat('a', 31));
    expect(fn () => LockBucketSecret::current())->toThrow(RuntimeException::class, 'too short');

    lockBucketSecrets(str_repeat('a', 32));
    expect(LockBucketSecret::current())->toBe(str_repeat('a', 32));
});

it('treats an unset or empty previous secret as no overlap', function (): void {
    lockBucketSecrets(str_repeat('a', 32), null, null);
    expect(LockBucketSecret::previous())->toBeNull()
        ->and(LockBucketSecret::all())->toBe([str_repeat('a', 32)]);

    lockBucketSecrets(str_repeat('a', 32), null, '');
    expect(LockBucketSecret::previous())->toBeNull();
});

it('refuses a previous secret shorter than 32 bytes', function (): void {
    lockBucketSecrets(str_repeat('a', 32), null, str_repeat('b', 31));

    expect(fn () => LockBucketSecret::previous())->toThrow(RuntimeException::class, 'VOUCH_LOCK_BUCKETS_PREVIOUS_SECRET')
        ->and(fn () => LockBucketSecret::assertConfigured())->toThrow(RuntimeException::class, 'too short');
});

it('validates both secrets in assertConfigured', function (): void {
    lockBucketSecrets(null);
    expect(fn () => LockBucketSecret::assertConfigured())->toThrow(RuntimeException::class, 'VOUCH_LOCK_BUCKETS_SECRET');

    lockBucketSecrets(str_repeat('a', 32), null, str_repeat('b', 32));
    LockBucketSecret::assertConfigured();

    expect(LockBucketSecret::all())->toBe([str_repeat('a', 32), str_repeat('b', 32)]);
});

it('locks only the current bucket when no rotation is in progress', function (): void {
    lockBucketSecrets(LOCK_BUCKET_GOLDEN_SECRET);

    expect(IssuanceLockBucket::buckets('recovery', 'email', 'ada@acme.example'))->toBe([3037]);
});

it('locks the bucket under both secrets, ascending, during a rotation overlap', function (): void {
    $new = str_repeat('n', 40);
    lockBucketSecrets($new);
    $underNew = IssuanceLockBucket::for('recovery', 'email', 'ada@acme.example');

    // Premise: the two secrets put this scope in different buckets.
    expect($underNew)->not->toBe(3037);

    lockBucketSecrets($new, null, LOCK_BUCKET_GOLDEN_SECRET);
    $buckets = IssuanceLockBucket::buckets('recovery', 'email', 'ADA@Acme.Example');

    $expected = [$underNew, 3037];
    sort($expected);

    expect($buckets)->toBe($expected)
        // for() is the CURRENT secret's bucket, not the previous one's.
        ->and(IssuanceLockBucket::for('recovery', 'email', 'ada@acme.example'))->toBe($underNew);
});

it('takes one bucket when both secrets map a scope to the same one', function (): void {
    $new = str_repeat('n', 40);

    for ($i = 0; $i < 200_000; $i++) {
        $value = sprintf('same-%d@acme.example', $i);
        lockBucketSecrets($new);
        $underNew = IssuanceLockBucket::for('recovery', 'email', $value);
        lockBucketSecrets(LOCK_BUCKET_GOLDEN_SECRET);

        if (IssuanceLockBucket::for('recovery', 'email', $value) === $underNew) {
            lockBucketSecrets($new, null, LOCK_BUCKET_GOLDEN_SECRET);

            expect(IssuanceLockBucket::buckets('recovery', 'email', $value))->toBe([$underNew]);

            return;
        }
    }

    throw new RuntimeException('No probed scope shared a bucket under both secrets.');
});

it('separates domains by the label inside the hashed message', function (): void {
    $differs = false;

    for ($i = 0; $i < 20; $i++) {
        $segment = sprintf('scope-%d', $i);
        $left = LockBucket::under(LOCK_BUCKET_GOLDEN_SECRET, 'issuance.mutex', $segment);
        $right = LockBucket::under(LOCK_BUCKET_GOLDEN_SECRET, 'throttle.ip', $segment);

        expect($left)->toBeGreaterThanOrEqual(0)->toBeLessThan(LockBucket::COUNT)
            ->and($right)->toBeGreaterThanOrEqual(0)->toBeLessThan(LockBucket::COUNT);

        $differs = $differs || $left !== $right;
    }

    expect($differs)->toBeTrue();
});

it('derives an IP bucket from the dimension and digest', function (): void {
    lockBucketSecrets(LOCK_BUCKET_GOLDEN_SECRET);
    $digest = str_repeat('ab', 32);

    $v4 = IpThrottleLockBucket::buckets('ipv4', $digest);
    $v6 = IpThrottleLockBucket::buckets('ipv6', $digest);

    expect($v4)->toHaveCount(1)
        ->and($v4)->toBe(IpThrottleLockBucket::buckets('ipv4', $digest))
        ->and($v4[0])->toBe(LockBucket::under(LOCK_BUCKET_GOLDEN_SECRET, IpThrottleLockBucket::DOMAIN, 'ipv4', $digest))
        ->and($v6[0])->toBe(LockBucket::under(LOCK_BUCKET_GOLDEN_SECRET, IpThrottleLockBucket::DOMAIN, 'ipv6', $digest));
});
