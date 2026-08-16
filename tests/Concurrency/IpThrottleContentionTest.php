<?php

declare(strict_types=1);

use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleSubject;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Expression;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

beforeEach(function (): void {
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['ip_lock_a', 'ip_lock_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'IP contention needs two connections to one file-backed SQLite database.',
        );
    }
});

function ipContentionSubject(ThrottleDimension $dimension, int $identity): ThrottleSubject
{
    return new ThrottleSubject(
        $dimension,
        str_pad(dechex($identity), 64, '0', STR_PAD_LEFT),
    );
}

function ipContentionStore(Connection $connection): DatabaseAuthThrottleStore
{
    return new DatabaseAuthThrottleStore(
        $connection,
        new DatabaseTime($connection),
        app(ThrottleConfiguration::class),
        new BoundedLockWait($connection),
        new LockContention(),
    );
}

function ipContentionSetting(Connection $connection): int|string
{
    $value = match ($connection->getDriverName()) {
        'sqlite' => $connection->scalar('PRAGMA busy_timeout'),
        'mysql' => $connection->scalar('SELECT @@SESSION.innodb_lock_wait_timeout'),
        'pgsql' => $connection->scalar('SHOW lock_timeout'),
        default => throw new RuntimeException('Unsupported IP contention driver.'),
    };

    if (! is_int($value) && ! is_string($value)) {
        throw new RuntimeException('The database returned a non-scalar lock-wait setting.');
    }

    return $value;
}

function setIpContentionSetting(Connection $connection, int|string $value): void
{
    match ($connection->getDriverName()) {
        'sqlite' => $connection->statement(sprintf('PRAGMA busy_timeout = %d', (int) $value)),
        'mysql' => $connection->statement(
            sprintf('SET SESSION innodb_lock_wait_timeout = %d', (int) $value),
        ),
        'pgsql' => $connection->scalar(
            "SELECT set_config('lock_timeout', ?, false)",
            [(string) $value],
        ),
        default => throw new RuntimeException('Unsupported IP contention driver.'),
    };
}

it('fails open for only the contended IP dimension and restores the host wait', function (): void {
    $ip = ipContentionSubject(ThrottleDimension::IpV4, 1);
    $tuple = ipContentionSubject(ThrottleDimension::IpIdentifier, 2);
    $now = new Expression('CURRENT_TIMESTAMP');

    DB::table('auth_throttle_ip_windows')->insert([
        'dimension' => $ip->dimension->value,
        'ip_digest' => $ip->digest,
        'window_started_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    $a = DB::connection('ip_lock_a');
    $b = DB::connection('ip_lock_b');
    $prior = ipContentionSetting($b);
    $parked = match ($b->getDriverName()) {
        'sqlite' => 47_000,
        'mysql' => 47,
        'pgsql' => '47s',
        default => throw new RuntimeException('Unsupported IP contention driver.'),
    };
    setIpContentionSetting($b, $parked);

    $a->beginTransaction();

    if ($a->getDriverName() === 'sqlite') {
        $a->table('auth_throttle_ip_windows')
            ->where('dimension', $ip->dimension->value)
            ->where('ip_digest', $ip->digest)
            ->update(['updated_at' => new Expression("datetime('now', '+1 second')")]);
    } else {
        $a->table('auth_throttle_ip_windows')
            ->where('dimension', $ip->dimension->value)
            ->where('ip_digest', $ip->digest)
            ->lockForUpdate()
            ->first();
    }

    $started = microtime(true);
    $state = null;
    $after = null;

    try {
        $state = ipContentionStore($b)->recordIpFailure($ip, $tuple);
        $after = ipContentionSetting($b);
    } finally {
        $a->rollBack();
        setIpContentionSetting($b, $prior);
    }

    expect($state)->toEqual(SharedThrottle::skipped())
        ->and($state->decision)->toBe(ThrottleDecision::Skipped)
        ->and($after)->toBe($parked)
        ->and(microtime(true) - $started)->toBeLessThan(5.0)
        ->and(DB::table('auth_throttle_tuples')->count())->toBe(0)
        ->and(DB::table('auth_throttle_locks')->count())->toBe(0);
});

it('does not swallow a missing tuple table as advisory contention', function (): void {
    $ip = ipContentionSubject(ThrottleDimension::IpV6, 1);
    $tuple = ipContentionSubject(ThrottleDimension::IpIdentifier, 2);

    DB::statement('DROP TABLE auth_throttle_tuples');

    expect(fn (): SharedThrottle => ipContentionStore(DB::connection('ip_lock_b'))
        ->recordIpFailure($ip, $tuple))
        ->toThrow(QueryException::class);
});
