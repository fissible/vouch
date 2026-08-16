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
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The IP contention matrix requires pcntl_fork.');
    }

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

function ipContentionEnforcementConfiguration(): ThrottleConfiguration
{
    $throttle = config()->array('vouch.throttle');
    $throttle['ip'] = [
        'mode' => 'enforce',
        'ipv6_observe_at' => 30,
        'ipv4_observe_at' => 300,
        'ipv6_enforce_at' => 2,
        'ipv4_enforce_at' => 3,
        'backoff_seconds' => 5,
    ];

    return ThrottleConfiguration::from(
        $throttle,
        config('vouch.otp.length'),
        config('vouch.totp.digits'),
        config('vouch.totp.window'),
    );
}

function ipContentionEnforcingStore(Connection $connection): DatabaseAuthThrottleStore
{
    return new DatabaseAuthThrottleStore(
        $connection,
        new DatabaseTime($connection),
        ipContentionEnforcementConfiguration(),
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

/**
 * Run two IP observations from separate processes after both connections have
 * crossed a ready barrier. A committed parent is held until both store calls
 * have started, so neither can finish before the common release.
 *
 * @param 'absent'|'active'|'expired' $parentState
 * @return array{decisions: list<string>, blockedWhileHeld: list<bool>, exitCodes: list<int>, outputs: list<string>, parentId: int|null, oldWindow: string|null}
 */
function raceIpObservations(bool $sameTuple, string $parentState): array
{
    $ip = ipContentionSubject(ThrottleDimension::IpV6, 1);
    $tuples = [
        ipContentionSubject(ThrottleDimension::IpIdentifier, 2),
        ipContentionSubject(ThrottleDimension::IpIdentifier, $sameTuple ? 2 : 3),
    ];
    $parentId = null;
    $oldWindow = null;
    $now = new Expression('CURRENT_TIMESTAMP');

    if ($parentState !== 'absent') {
        $parentId = DB::table('auth_throttle_ip_windows')->insertGetId([
            'dimension' => $ip->dimension->value,
            'ip_digest' => $ip->digest,
            'window_started_at' => $now,
            'created_at' => $now,
            'updated_at' => $now,
        ]);

        if ($parentState === 'expired') {
            DB::update(
                'UPDATE auth_throttle_ip_windows SET window_started_at = '
                . (new DatabaseTime(DB::connection()))->deadlineSqlHere()
                . ' WHERE id = ?',
                [-900, $parentId],
            );
            $oldWindowValue = DB::table('auth_throttle_ip_windows')
                ->where('id', $parentId)
                ->value('window_started_at');

            if (! is_string($oldWindowValue)) {
                throw new RuntimeException('The race fixture returned an invalid old IP window.');
            }

            $oldWindow = $oldWindowValue;
            DB::table('auth_throttle_tuples')->insert([
                'ip_window_id' => $parentId,
                'window_started_at' => $oldWindow,
                'tuple_digest' => ipContentionSubject(
                    ThrottleDimension::IpIdentifier,
                    99,
                )->digest,
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        }
    }

    $directory = sys_get_temp_dir() . '/vouch-ip-race-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create IP contention barrier directory.');
    }

    $release = $directory . '/release';
    $children = [];
    $blocked = [];
    $parent = null;
    $sqliteImmediate = false;

    DB::purge();

    try {
        foreach ($tuples as $index => $tuple) {
            $pid = pcntl_fork();

            if ($pid === -1) {
                throw new RuntimeException('Could not fork IP contention child.');
            }

            if ($pid === 0) {
                $ready = $directory . "/ready-{$index}";
                $started = $directory . "/started-{$index}";
                $output = $directory . "/output-{$index}";
                $database = $directory . "/database-{$index}";

                try {
                    $connection = DB::connection();
                    $connection->getPdo();

                    if ($connection->getDriverName() === 'sqlite') {
                        $connection->statement('PRAGMA busy_timeout = 5000');
                    }

                    file_put_contents($database, $connection->getDatabaseName());
                    touch($ready);
                    $deadline = microtime(true) + 10.0;

                    while (! is_file($release)) {
                        if (microtime(true) >= $deadline) {
                            throw new RuntimeException('Timed out waiting for the IP race release.');
                        }

                        usleep(1_000);
                    }

                    touch($started);
                    $state = ipContentionEnforcingStore($connection)
                        ->recordIpFailure($ip, $tuple);
                    file_put_contents($output, $state->decision->name);
                    exit(0);
                } catch (Throwable $exception) {
                    file_put_contents($output, $exception::class . ': ' . $exception->getMessage());
                    exit(1);
                }
            }

            $children[$index] = $pid;
        }

        $barrierDeadline = microtime(true) + 10.0;

        foreach (array_keys($tuples) as $index) {
            while (! is_file($directory . "/ready-{$index}")) {
                if (microtime(true) >= $barrierDeadline) {
                    throw new RuntimeException('An IP race child did not reach the ready barrier.');
                }

                usleep(1_000);
            }
        }

        $parent = DB::connection();
        $parentDatabase = $parent->getDatabaseName();

        foreach (array_keys($tuples) as $index) {
            if (file_get_contents($directory . "/database-{$index}") !== $parentDatabase) {
                throw new RuntimeException("IP race child {$index} used a different database.");
            }
        }

        if ($parentState !== 'absent') {
            $sqliteImmediate = $parent->getDriverName() === 'sqlite';

            if ($sqliteImmediate) {
                $parent->statement('BEGIN IMMEDIATE');
                $parent->table('auth_throttle_ip_windows')
                    ->where('id', $parentId)
                    ->update(['updated_at' => new Expression("datetime('now', '+1 second')")]);
            } else {
                $parent->beginTransaction();
                $parent->table('auth_throttle_ip_windows')
                    ->where('id', $parentId)
                    ->lockForUpdate()
                    ->first();
            }
        }

        touch($release);

        foreach (array_keys($tuples) as $index) {
            while (! is_file($directory . "/started-{$index}")) {
                if (microtime(true) >= $barrierDeadline) {
                    throw new RuntimeException('An IP race child did not start its store call.');
                }

                usleep(1_000);
            }
        }

        if ($parentState !== 'absent') {
            usleep(200_000);

            foreach (array_keys($children) as $index) {
                $blocked[] = ! is_file($directory . "/output-{$index}");
            }

            if ($sqliteImmediate) {
                $parent->statement('COMMIT');
            } else {
                $parent->commit();
            }
        }
    } catch (Throwable $exception) {
        touch($release);

        if ($parent !== null && $sqliteImmediate) {
            $parent->statement('ROLLBACK');
        } elseif ($parent !== null && $parent->transactionLevel() > 0) {
            $parent->rollBack();
        }

        throw $exception;
    }

    $exitCodes = [];
    $outputs = [];

    foreach ($children as $index => $pid) {
        $status = 0;
        pcntl_waitpid($pid, $status);
        $exitCode = pcntl_wifexited($status) ? pcntl_wexitstatus($status) : false;
        $exitCodes[] = is_int($exitCode) ? $exitCode : 255;
        $path = $directory . "/output-{$index}";
        $outputs[] = is_file($path) ? (string) file_get_contents($path) : 'missing output';
    }

    foreach (glob($directory . '/*') ?: [] as $path) {
        unlink($path);
    }

    rmdir($directory);

    return [
        'decisions' => $outputs,
        'blockedWhileHeld' => $blocked,
        'exitCodes' => $exitCodes,
        'outputs' => $outputs,
        'parentId' => $parentId,
        'oldWindow' => $oldWindow,
    ];
}

it('serializes each tuple and parent-generation contention cell', function (
    bool $sameTuple,
    string $parentState,
): void {
    if (! in_array($parentState, ['absent', 'active', 'expired'], true)) {
        throw new InvalidArgumentException('The IP contention parent state is invalid.');
    }

    $race = raceIpObservations($sameTuple, $parentState);
    $ip = ipContentionSubject(ThrottleDimension::IpV6, 1);
    $parentRaw = DB::table('auth_throttle_ip_windows')
        ->where('dimension', $ip->dimension->value)
        ->where('ip_digest', $ip->digest)
        ->firstOrFail(['id', 'window_started_at']);
    $parent = (array) $parentRaw;
    $parentId = $parent['id'] ?? null;
    $window = $parent['window_started_at'] ?? null;

    if (! is_int($parentId) || ! is_string($window)) {
        throw new RuntimeException('The IP race returned an invalid parent row.');
    }

    $decisions = $race['decisions'];
    sort($decisions);
    $expectedDecisions = $sameTuple
        ? ['Permitted', 'Permitted']
        : ['BackedOff', 'Permitted'];
    $currentMarkers = DB::table('auth_throttle_tuples')
        ->where('ip_window_id', $parentId)
        ->where('window_started_at', $window)
        ->count();
    $totalMarkers = DB::table('auth_throttle_tuples')
        ->where('ip_window_id', $parentId)
        ->count();

    expect($race['exitCodes'])->toBe([0, 0], implode("\n", $race['outputs']))
        ->and($decisions)->toBe($expectedDecisions)
        ->and($currentMarkers)->toBe($sameTuple ? 1 : 2)
        ->and(DB::table('auth_throttle_ip_windows')->count())->toBe(1);

    if ($parentState === 'absent') {
        expect($race['blockedWhileHeld'])->toBe([])
            ->and($race['parentId'])->toBeNull()
            ->and($totalMarkers)->toBe($sameTuple ? 1 : 2);

        return;
    }

    expect($race['blockedWhileHeld'])->toBe([true, true])
        ->and($parentId)->toBe($race['parentId']);

    if ($parentState === 'expired') {
        expect($window)->not->toBe($race['oldWindow'])
            ->and($totalMarkers)->toBe(($sameTuple ? 1 : 2) + 1);
    } else {
        expect($race['oldWindow'])->toBeNull()
            ->and($totalMarkers)->toBe($sameTuple ? 1 : 2);
    }
})->with([
    'same tuple, absent parent' => [true, 'absent'],
    'distinct tuple, absent parent' => [false, 'absent'],
    'same tuple, committed parent' => [true, 'active'],
    'distinct tuple, committed parent' => [false, 'active'],
    'same tuple, expired parent' => [true, 'expired'],
    'distinct tuple, expired parent' => [false, 'expired'],
]);

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

it('keeps the identifier lock when the later advisory IP transaction times out', function (): void {
    $identifier = ipContentionSubject(ThrottleDimension::Identifier, 10);
    $ip = ipContentionSubject(ThrottleDimension::IpV4, 1);
    $tuple = ipContentionSubject(ThrottleDimension::IpIdentifier, 2);
    $now = new Expression('CURRENT_TIMESTAMP');

    DB::table('auth_throttle_counters')->insert([
        'dimension' => $identifier->dimension->value,
        'subject_digest' => $identifier->digest,
        'window_started_at' => $now,
        'count' => 9,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    DB::update(
        'UPDATE auth_throttle_counters SET window_started_at = '
        . (new DatabaseTime(DB::connection()))->deadlineSqlHere()
        . ' WHERE subject_digest = ?',
        [-32, $identifier->digest],
    );
    DB::table('auth_throttle_ip_windows')->insert([
        'dimension' => $ip->dimension->value,
        'ip_digest' => $ip->digest,
        'window_started_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    $a = DB::connection('ip_lock_a');
    $b = DB::connection('ip_lock_b');
    $store = ipContentionStore($b);

    // The authoritative transaction commits before any shared lock wait.
    $identifierState = $store->recordIdentifierFailure($identifier);

    $a->beginTransaction();

    if ($a->getDriverName() === 'sqlite') {
        $a->table('auth_throttle_ip_windows')
            ->where('ip_digest', $ip->digest)
            ->update(['updated_at' => new Expression("datetime('now', '+1 second')")]);
    } else {
        $a->table('auth_throttle_ip_windows')
            ->where('ip_digest', $ip->digest)
            ->lockForUpdate()
            ->first();
    }

    try {
        $sharedState = $store->recordIpFailure($ip, $tuple);
    } finally {
        $a->rollBack();
    }

    expect($identifierState->decision)->toBe(ThrottleDecision::Locked)
        ->and($sharedState)->toEqual(SharedThrottle::skipped())
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', ThrottleDimension::Identifier->value)
            ->where('subject_digest', $identifier->digest)
            ->value('count'))->toBe(10)
        ->and(DB::table('auth_throttle_locks')
            ->where('subject_digest', $identifier->digest)
            ->count())->toBe(1)
        ->and(DB::table('auth_throttle_tuples')->count())->toBe(0);
});

it('does not swallow a missing tuple table as advisory contention', function (): void {
    $ip = ipContentionSubject(ThrottleDimension::IpV6, 1);
    $tuple = ipContentionSubject(ThrottleDimension::IpIdentifier, 2);

    DB::statement('DROP TABLE auth_throttle_tuples');

    expect(fn (): SharedThrottle => ipContentionStore(DB::connection('ip_lock_b'))
        ->recordIpFailure($ip, $tuple))
        ->toThrow(QueryException::class);
});

it('does not swallow a missing tuple column as advisory contention', function (): void {
    $ip = ipContentionSubject(ThrottleDimension::IpV6, 1);
    $tuple = ipContentionSubject(ThrottleDimension::IpIdentifier, 2);

    Schema::table('auth_throttle_tuples', function (Blueprint $table): void {
        $table->renameColumn('tuple_digest', 'broken_tuple_digest');
    });

    expect(fn (): SharedThrottle => ipContentionStore(DB::connection('ip_lock_b'))
        ->recordIpFailure($ip, $tuple))
        ->toThrow(QueryException::class);
});
