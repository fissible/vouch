<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\IpThrottleLockBucket;
use Fissible\Vouch\Support\LockBucket;
use Fissible\Vouch\Support\LockBucketSecret;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleSubject;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/*
 * #16. The IP bucket is the mutex: a failed login and a prune both take it.
 *
 * A second connection holds one bucket. Each case pairs with a control holding
 * a DIFFERENT bucket, so "it waited" is caused by the bucket and not by anything
 * else the path locks.
 *
 * DatabaseMigrations rather than RefreshDatabase: the store's own transaction
 * must be the outermost, or a lock timeout surfaces as Laravel's nested-
 * transaction DeadlockException instead of the QueryException the store's
 * bounded wait classifies. SQLite is skipped: row locks are no-ops there.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite') {
        $this->markTestSkipped('Row locks are a no-op on SQLite.');
    }

    $default = Config::string('database.default');
    config([
        'database.connections.ip_bucket_holder' => Config::array('database.connections.' . $default),
        'database.connections.ip_bucket_observer' => Config::array('database.connections.' . $default),
    ]);
});

afterEach(function (): void {
    // beforeEach skips SQLite before configuring the holder, so there is none.
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite') {
        return;
    }

    $holder = DB::connection('ip_bucket_holder');

    if ($holder->transactionLevel() > 0) {
        $holder->rollBack();
    }

    DB::purge('ip_bucket_holder');
    DB::purge('ip_bucket_observer');
    // The default connection's lock wait was shortened for a prune case.
    DB::purge();
});

function ipBucketDigest(int $identity): string
{
    return str_pad(dechex($identity), 64, '0', STR_PAD_LEFT);
}

function ipBucketSubject(): ThrottleSubject
{
    return new ThrottleSubject(ThrottleDimension::IpV4, ipBucketDigest(7));
}

/**
 * The bucket a subject's lock takes under the configured secrets, and one it does not.
 *
 * @return array{own: int, other: int}
 */
function ipBucketPair(string $digest): array
{
    $own = IpThrottleLockBucket::buckets('ipv4', $digest);
    $other = ($own[0] + 1) % LockBucket::COUNT;

    while (in_array($other, $own, true)) {
        $other = ($other + 1) % LockBucket::COUNT;
    }

    return ['own' => $own[0], 'other' => $other];
}

function holdIpBucket(int $bucket): void
{
    $holder = DB::connection('ip_bucket_holder');
    $holder->beginTransaction();

    if ($holder->table(IpThrottleLockBucket::TABLE)->where('bucket', $bucket)->lockForUpdate()->first() === null) {
        throw new RuntimeException("IP bucket {$bucket} is not seeded.");
    }
}

function ipBucketStore(): DatabaseAuthThrottleStore
{
    $connection = DB::connection();

    return new DatabaseAuthThrottleStore(
        $connection,
        new DatabaseTime($connection),
        app(ThrottleConfiguration::class),
        new BoundedLockWait($connection),
        new LockContention(),
    );
}

function recordIpBucketFailure(): ThrottleDecision
{
    return ipBucketStore()->recordIpFailure(
        ipBucketSubject(),
        new ThrottleSubject(ThrottleDimension::IpIdentifier, ipBucketDigest(8)),
    )->decision;
}

function ipBucketTuples(): int
{
    return DB::table('auth_throttle_tuples')->count();
}

function shortenIpBucketLockWait(Connection $connection): void
{
    match ($connection->getDriverName()) {
        'mysql' => $connection->statement('SET SESSION innodb_lock_wait_timeout = 1'),
        'pgsql' => $connection->statement("SELECT set_config('lock_timeout', '1s', false)"),
        default => throw new RuntimeException('Unsupported IP bucket driver.'),
    };
}

function expiredIpBucketWindow(): int
{
    $now = app(DatabaseTime::class)->current();
    $started = $now->sub(new DateInterval(sprintf(
        'PT%dS',
        app(ThrottleConfiguration::class)->windowSeconds + 3600,
    )));

    return DB::table('auth_throttle_ip_windows')->insertGetId([
        'dimension' => 'ipv4',
        'ip_digest' => ipBucketSubject()->digest,
        'window_started_at' => $started,
        'created_at' => $started,
        'updated_at' => $started,
    ]);
}

it('skips recording an IP failure while its bucket is held', function (): void {
    holdIpBucket(ipBucketPair(ipBucketSubject()->digest)['own']);

    expect(recordIpBucketFailure())->toBe(ThrottleDecision::Skipped)
        ->and(ipBucketTuples())->toBe(0);
});

it('records an IP failure while a different bucket is held', function (): void {
    holdIpBucket(ipBucketPair(ipBucketSubject()->digest)['other']);

    expect(recordIpBucketFailure())->not->toBe(ThrottleDecision::Skipped)
        ->and(ipBucketTuples())->toBe(1);
});

it('waits on the previous secret bucket during a rotation overlap', function (): void {
    $old = 'oooooooooooooooooooooooooooooooo-old-ip-rotation';
    $new = 'nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn-new-ip-rotation';
    config([LockBucketSecret::KEY => $old, LockBucketSecret::LEGACY_KEY => null, LockBucketSecret::PREVIOUS_KEY => null]);
    $oldBucket = IpThrottleLockBucket::buckets('ipv4', ipBucketSubject()->digest)[0];
    config([LockBucketSecret::KEY => $new]);
    $newBucket = IpThrottleLockBucket::buckets('ipv4', ipBucketSubject()->digest)[0];

    // Premise: the secrets disagree for this IP, so the two outcomes differ.
    expect($newBucket)->not->toBe($oldBucket);

    holdIpBucket($oldBucket);

    // The new secret alone proceeds past the old bucket: the uncoordinated case.
    expect(recordIpBucketFailure())->not->toBe(ThrottleDecision::Skipped);

    config([LockBucketSecret::PREVIOUS_KEY => $old]);

    expect(recordIpBucketFailure())->toBe(ThrottleDecision::Skipped);
});

it('does not reclaim an expired window while its bucket is held', function (): void {
    $window = expiredIpBucketWindow();
    holdIpBucket(ipBucketPair(ipBucketSubject()->digest)['own']);
    shortenIpBucketLockWait(DB::connection());

    expect(Artisan::call('vouch:prune'))->toBe(CommandExit::Failure->value)
        ->and(Artisan::output())->toContain('failed reclaiming expired IP windows')
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $window)->exists())->toBeTrue();
});

it('reclaims an expired window while a different bucket is held', function (): void {
    $window = expiredIpBucketWindow();
    holdIpBucket(ipBucketPair(ipBucketSubject()->digest)['other']);
    shortenIpBucketLockWait(DB::connection());

    expect(Artisan::call('vouch:prune'))->toBe(CommandExit::Success->value)
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $window)->exists())->toBeFalse();
});

/**
 * Whether some transaction on this test database is waiting for a row lock.
 *
 * Asked on its own connection, outside any transaction. PostgreSQL caches
 * pg_stat_activity for the rest of a transaction, so polling from the holder
 * would keep returning the first answer and never see the waiter arrive.
 */
function ipBucketSomeoneWaits(): bool
{
    $observer = DB::connection('ip_bucket_observer');

    $waiting = match ($observer->getDriverName()) {
        'pgsql' => $observer->scalar(
            "SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()",
        ),
        'mysql' => $observer->scalar(
            'SELECT COUNT(*) FROM performance_schema.data_lock_waits w
             JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID
             WHERE l.OBJECT_SCHEMA = DATABASE()',
        ),
        default => throw new RuntimeException('Unsupported IP bucket driver.'),
    };

    return is_numeric($waiting) && (int) $waiting > 0;
}

it('keeps a window that was renewed while prune waited for its bucket', function (): void {
    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('A genuine interleave needs pcntl_fork.');
    }

    /*
     * The recheck under the bucket is what makes reclamation safe: prune selects
     * candidates without a lock, so a login can renew a window between that
     * select and the delete. A delete keyed on id alone would remove a live
     * window. The child is observed WAITING on the bucket before the renewal
     * commits, so the candidate select provably saw the window as expired.
     */
    $window = expiredIpBucketWindow();
    $result = sys_get_temp_dir() . '/vouch-ip-renewal-' . bin2hex(random_bytes(8));

    holdIpBucket(ipBucketPair(ipBucketSubject()->digest)['own']);
    DB::connection('ip_bucket_holder')->table('auth_throttle_ip_windows')
        ->where('id', $window)
        ->update(['window_started_at' => app(DatabaseTime::class)->current()]);

    DB::purge();
    $pid = pcntl_fork();

    if ($pid === -1) {
        throw new RuntimeException('Could not fork a child.');
    }

    if ($pid === 0) {
        try {
            $connection = DB::connection();
            match ($connection->getDriverName()) {
                'mysql' => $connection->statement('SET SESSION innodb_lock_wait_timeout = 15'),
                'pgsql' => $connection->statement("SELECT set_config('lock_timeout', '15s', false)"),
                default => null,
            };
            $reclaimed = (new Fissible\Vouch\Throttle\IpWindowReclaimer(
                $connection,
                new DatabaseTime($connection),
                app(ThrottleConfiguration::class),
            ))->reclaim();
            file_put_contents($result, (string) $reclaimed);
            exit(0);
        } catch (Throwable $exception) {
            file_put_contents($result, 'error: ' . $exception->getMessage());
            exit(1);
        }
    }

    $observedWaiting = false;
    $deadline = microtime(true) + 10.0;

    while (microtime(true) < $deadline) {
        if (ipBucketSomeoneWaits()) {
            $observedWaiting = true;

            break;
        }

        usleep(20_000);
    }

    DB::connection('ip_bucket_holder')->commit();
    pcntl_waitpid($pid, $status);
    $reported = is_file($result) ? (string) file_get_contents($result) : 'no result';
    @unlink($result);

    // Premise first: prune really was blocked on the bucket when the renewal
    // committed. Without it, a child that never saw the window passes too.
    expect($observedWaiting)->toBeTrue('prune was never observed waiting; the child reported: ' . $reported)
        ->and($reported)->toBe('0')
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $window)->exists())->toBeTrue();
});
