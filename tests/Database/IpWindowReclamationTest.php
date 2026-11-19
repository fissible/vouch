<?php

declare(strict_types=1);

use Fissible\Vouch\Console\RetentionManifest;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\IpThrottleLockBucket;
use Fissible\Vouch\Support\LockBucket;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleSubject;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

/*
 * #16. IP windows stop being their own mutex, so pruning can reclaim them.
 */
uses(RefreshDatabase::class);

function ipReclaimDigest(int $identity): string
{
    return str_pad(dechex($identity), 64, '0', STR_PAD_LEFT);
}

/** Insert one IP window whose window started $ageSeconds before database now. */
function ipReclaimWindow(string $digest, int $ageSeconds): int
{
    $now = app(DatabaseTime::class)->current();
    $started = $now->sub(new DateInterval(sprintf('PT%dS', $ageSeconds)));

    return DB::table('auth_throttle_ip_windows')->insertGetId([
        'dimension' => 'ipv4',
        'ip_digest' => $digest,
        'window_started_at' => $started,
        'created_at' => $started,
        'updated_at' => $started,
    ]);
}

function ipReclaimTuple(int $windowId, string $digest): int
{
    $now = app(DatabaseTime::class)->current();

    return DB::table('auth_throttle_tuples')->insertGetId([
        'ip_window_id' => $windowId,
        // Current, so only the cascade -- not the tuple prune -- can remove it.
        'window_started_at' => $now,
        'tuple_digest' => $digest,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
}

function ipReclaimWindowSeconds(): int
{
    return app(ThrottleConfiguration::class)->windowSeconds;
}

function ipReclaimEnforcingStore(): DatabaseAuthThrottleStore
{
    $throttle = config()->array('vouch.throttle');
    $throttle['ip'] = [
        'mode' => 'enforce',
        'ipv6_observe_at' => 30,
        'ipv4_observe_at' => 300,
        'ipv6_enforce_at' => 2,
        'ipv4_enforce_at' => 3,
        'backoff_seconds' => 60,
    ];
    $connection = DB::connection();

    return new DatabaseAuthThrottleStore(
        $connection,
        new DatabaseTime($connection),
        ThrottleConfiguration::from(
            $throttle,
            config('vouch.otp.length'),
            config('vouch.totp.digits'),
            config('vouch.totp.window'),
        ),
        new BoundedLockWait($connection),
        new LockContention(),
    );
}

it('seeds every IP lock bucket', function (): void {
    $buckets = DB::table(IpThrottleLockBucket::TABLE)->orderBy('bucket')->pluck('bucket')
        ->map(static fn (mixed $bucket): int => is_numeric($bucket) ? (int) $bucket : -1)
        ->all();

    expect($buckets)->toBe(range(0, LockBucket::COUNT - 1));
});

it('reclaims an expired IP window with its tuples and keeps a live one', function (): void {
    $window = ipReclaimWindowSeconds();
    // An hour past expiry, so app/database clock skew cannot move the case.
    $expired = ipReclaimWindow(ipReclaimDigest(1), $window + 3600);
    $live = ipReclaimWindow(ipReclaimDigest(2), 0);
    $orphanedTuple = ipReclaimTuple($expired, ipReclaimDigest(3));
    $liveTuple = ipReclaimTuple($live, ipReclaimDigest(4));

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(Artisan::output())->toContain('Pruned 1 expired IP window(s).')
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $expired)->exists())->toBeFalse()
        ->and(DB::table('auth_throttle_tuples')->where('id', $orphanedTuple)->exists())->toBeFalse()
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $live)->exists())->toBeTrue()
        ->and(DB::table('auth_throttle_tuples')->where('id', $liveTuple)->exists())->toBeTrue();
});

it('reclaims at the same expiry boundary the throttle reads', function (): void {
    $window = ipReclaimWindowSeconds();
    // Exactly the window old by the clock sampled now: expired by the time
    // prune samples its own, later, database now.
    $atBoundary = ipReclaimWindow(ipReclaimDigest(5), $window);
    // A minute short of expiry.
    $inside = ipReclaimWindow(ipReclaimDigest(6), $window - 60);

    Artisan::call('vouch:prune');

    expect(DB::table('auth_throttle_ip_windows')->where('id', $atBoundary)->exists())->toBeFalse()
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $inside)->exists())->toBeTrue();
});

it('reclaims every expired window in more than one batch', function (): void {
    $window = ipReclaimWindowSeconds();

    for ($i = 0; $i < 600; $i++) {
        ipReclaimWindow(ipReclaimDigest(1000 + $i), $window + 3600);
    }

    expect(Artisan::call('vouch:prune'))->toBe(0)
        ->and(Artisan::output())->toContain('Pruned 600 expired IP window(s).')
        ->and(DB::table('auth_throttle_ip_windows')->count())->toBe(0);
});

it('keeps two IPs that share a bucket in separate windows', function (): void {
    /*
     * False sharing is latency only. Two IPs in one bucket serialize, but one
     * IP's failures must never count against the other.
     */
    $seen = [];
    $pair = null;

    for ($i = 0; $i < 5000 && $pair === null; $i++) {
        $digest = ipReclaimDigest(20_000 + $i);
        $bucket = IpThrottleLockBucket::buckets('ipv4', $digest)[0];

        if (isset($seen[$bucket])) {
            $pair = [$seen[$bucket], $digest];
        }

        $seen[$bucket] = $digest;
    }

    expect($pair)->not->toBeNull();
    [$noisy, $quiet] = $pair ?? ['', ''];

    $store = ipReclaimEnforcingStore();
    $last = null;

    for ($i = 0; $i < 3; $i++) {
        $last = $store->recordIpFailure(
            new ThrottleSubject(ThrottleDimension::IpV4, $noisy),
            new ThrottleSubject(ThrottleDimension::IpIdentifier, ipReclaimDigest(30_000 + $i)),
        );
    }

    // Premise: the noisy IP really did reach its threshold.
    expect($last->decision)->toBe(ThrottleDecision::BackedOff);

    $quietResult = $store->recordIpFailure(
        new ThrottleSubject(ThrottleDimension::IpV4, $quiet),
        new ThrottleSubject(ThrottleDimension::IpIdentifier, ipReclaimDigest(40_000)),
    );

    expect($quietResult->decision)->toBe(ThrottleDecision::Permitted);
});

it('declares IP windows pruned and the IP lock buckets retained', function (): void {
    expect(RetentionManifest::pruned())->toHaveKey('auth_throttle_ip_windows')
        ->and(RetentionManifest::retained())->toHaveKey(IpThrottleLockBucket::TABLE)
        ->and(RetentionManifest::unreclaimed())->not->toHaveKey('auth_throttle_ip_windows');
});
