<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleSubject;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The scalar contention proof requires pcntl_fork.');
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'The scalar contention proof needs two processes connected to one file-backed database.',
        );
    }
});

function scalarRaceSubject(int $identity): ThrottleSubject
{
    return new ThrottleSubject(
        ThrottleDimension::Identifier,
        str_pad(dechex($identity), 64, '0', STR_PAD_LEFT),
    );
}

function seedScalarRaceSubject(ThrottleSubject $subject): void
{
    $now = new \Illuminate\Database\Query\Expression('CURRENT_TIMESTAMP');

    DB::table('auth_throttle_counters')->insert([
        'dimension' => $subject->dimension->value,
        'subject_digest' => $subject->digest,
        'window_started_at' => $now,
        'count' => 0,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
}

/**
 * @param list<ThrottleSubject> $subjects
 * @return array{blockedWhileLocked: list<bool>, exitCodes: list<int>, outputs: list<string>}
 */
function raceScalarFailures(array $subjects, bool $issuance = false): array
{
    $directory = sys_get_temp_dir() . '/vouch-scalar-race-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create scalar contention barrier directory.');
    }

    $release = $directory . '/release';
    $children = [];
    $blocked = [];
    $parent = null;
    $sqliteImmediate = false;

    // SQLite connections are not fork-safe even if the child immediately
    // purges its inherited PDO. Close the migration/seed connection before
    // forking; every process opens its own handle afterwards.
    DB::purge();

    try {
        foreach ($subjects as $index => $subject) {
            $pid = pcntl_fork();

            if ($pid === -1) {
                throw new RuntimeException('Could not fork scalar contention child.');
            }

            if ($pid === 0) {
                $ready = $directory . "/ready-{$index}";
                $started = $directory . "/started-{$index}";
                $output = $directory . "/output-{$index}";
                $database = $directory . "/database-{$index}";

                try {
                    // Opening a fresh connection before declaring ready is part
                    // of the non-vacuity proof: both children are real database
                    // peers, and no process inherited an open SQLite handle.
                    $connection = DB::connection();
                    $connection->getPdo();

                    if ($connection->getDriverName() === 'sqlite') {
                        // The forked connection does not pass through
                        // Testbench's normal per-test readback path. Set the
                        // same bounded wait explicitly so SQLITE_BUSY means
                        // "wait for the parent release", not "fail instantly".
                        $connection->statement('PRAGMA busy_timeout = 5000');
                    }

                    file_put_contents($database, $connection->getDatabaseName());
                    touch($ready);

                    $deadline = microtime(true) + 10.0;

                    while (! is_file($release)) {
                        if (microtime(true) >= $deadline) {
                            throw new RuntimeException('Timed out waiting for scalar race release.');
                        }

                        usleep(1_000);
                    }

                    touch($started);

                    $store = new DatabaseAuthThrottleStore(
                        $connection,
                        new DatabaseTime($connection),
                        app(ThrottleConfiguration::class),
                    );
                    $result = $issuance
                        ? $store->permitIssuance($subject)->name
                        : (function () use ($store, $subject): string {
                            $store->recordIdentifierFailure($subject);

                            return 'ok';
                        })();
                    file_put_contents($output, $result);
                    exit(0);
                } catch (Throwable $exception) {
                    file_put_contents($output, $exception::class . ': ' . $exception->getMessage());
                    exit(1);
                }
            }

            $children[$index] = $pid;
        }

        $barrierDeadline = microtime(true) + 10.0;

        foreach (array_keys($subjects) as $index) {
            while (! is_file($directory . "/ready-{$index}")) {
                if (microtime(true) >= $barrierDeadline) {
                    throw new RuntimeException('A scalar race child did not reach the ready barrier.');
                }

                usleep(1_000);
            }
        }

        $parent = DB::connection();
        $parentDatabase = $parent->getDatabaseName();

        if ($parent->getDriverName() === 'sqlite'
            && $parentDatabase !== (string) getenv('VOUCH_SQLITE_PATH')) {
            throw new RuntimeException(
                'Scalar race parent resolved unexpected SQLite database: ' . $parentDatabase,
            );
        }

        foreach (array_keys($subjects) as $index) {
            $childDatabase = file_get_contents($directory . "/database-{$index}");

            if ($childDatabase !== $parentDatabase) {
                throw new RuntimeException(
                    "Scalar race child {$index} connected to a different database.",
                );
            }
        }

        $sqliteImmediate = $parent->getDriverName() === 'sqlite';

        if ($sqliteImmediate) {
            // PDO::beginTransaction() is deferred on SQLite. BEGIN IMMEDIATE
            // makes the held-writer premise explicit before either child is
            // released, rather than hoping the following statement upgrades it.
            $parent->statement('BEGIN IMMEDIATE');
        } else {
            $parent->beginTransaction();
        }

        // Change an operational timestamp, never the count under test. The
        // one-second move prevents SQLite from optimizing a no-value-change
        // UPDATE away before it acquires the database-wide writer lock.
        $future = match ($parent->getDriverName()) {
            'sqlite' => "datetime('now', '+1 second')",
            'mysql' => 'DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 1 SECOND)',
            'pgsql' => "CURRENT_TIMESTAMP(0) + INTERVAL '1 second'",
            default => throw new RuntimeException('Unsupported scalar race driver.'),
        };

        $lockedRows = $parent->table('auth_throttle_counters')
            ->whereIn('subject_digest', array_map(
                static fn (ThrottleSubject $subject): string => $subject->digest,
                $subjects,
            ))
            ->update(['updated_at' => new \Illuminate\Database\Query\Expression($future)]);

        if ($lockedRows !== count(array_unique(array_map(
            static fn (ThrottleSubject $subject): string => $subject->digest,
            $subjects,
        )))) {
            throw new RuntimeException('The parent did not lock every scalar race row.');
        }

        if ($sqliteImmediate) {
            if (! $parent->getPdo()->inTransaction()) {
                throw new RuntimeException('SQLite BEGIN IMMEDIATE did not open a transaction.');
            }

            $settings = config()->array('database.connections.sqlite');
            $settings['busy_timeout'] = 10;
            config(['database.connections.scalar_lock_probe' => $settings]);
            $probe = DB::connection('scalar_lock_probe');
            $contended = false;

            try {
                $probe->table('auth_throttle_counters')
                    ->where('subject_digest', $subjects[0]->digest)
                    ->update(['updated_at' => new \Illuminate\Database\Query\Expression($future)]);
            } catch (\Illuminate\Database\QueryException) {
                $contended = true;
            } finally {
                DB::purge('scalar_lock_probe');
            }

            if (! $contended) {
                throw new RuntimeException('The SQLite parent transaction did not hold the writer lock.');
            }
        }

        touch($release);

        foreach (array_keys($subjects) as $index) {
            while (! is_file($directory . "/started-{$index}")) {
                if (microtime(true) >= $barrierDeadline) {
                    throw new RuntimeException('A scalar race child did not start its store call.');
                }

                usleep(1_000);
            }
        }

        usleep(200_000);

        foreach (array_keys($children) as $index) {
            // A child writes output only after the store call returns. Absence
            // here proves both calls are still inside the held-lock interval;
            // unlike WNOHANG this is not affected by Pest's process handling.
            $blocked[] = ! is_file($directory . "/output-{$index}");
        }

        if ($sqliteImmediate) {
            $parent->statement('COMMIT');
        } else {
            $parent->commit();
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
        'blockedWhileLocked' => $blocked,
        'exitCodes' => $exitCodes,
        'outputs' => $outputs,
    ];
}

it('records two racing failures for one subject exactly', function (): void {
    $subject = scalarRaceSubject(1);
    seedScalarRaceSubject($subject);

    $race = raceScalarFailures([$subject, $subject]);
    $count = DB::table('auth_throttle_counters')
        ->where('dimension', $subject->dimension->value)
        ->where('subject_digest', $subject->digest)
        ->value('count');

    expect($race['exitCodes'])->toBe([0, 0], implode("\n", $race['outputs']))
        ->and($race['blockedWhileLocked'])->toBe([true, true])
        ->and($race['outputs'])->toBe(['ok', 'ok'])
        ->and($count)->toBe(2);
});

it('admits exactly one of two issuances racing at the fifth-event boundary', function (): void {
    $subject = new ThrottleSubject(
        ThrottleDimension::Issuance,
        str_repeat('e', 64),
    );
    seedScalarRaceSubject($subject);
    DB::table('auth_throttle_counters')
        ->where('dimension', ThrottleDimension::Issuance->value)
        ->where('subject_digest', $subject->digest)
        ->update(['count' => 4]);

    $race = raceScalarFailures([$subject, $subject], issuance: true);
    $outputs = $race['outputs'];
    sort($outputs);

    expect($race['exitCodes'])->toBe([0, 0], implode("\n", $race['outputs']))
        ->and($race['blockedWhileLocked'])->toBe([true, true])
        ->and($outputs)->toBe(['Permitted', 'Refused'])
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', ThrottleDimension::Issuance->value)
            ->where('subject_digest', $subject->digest)
            ->value('count'))->toBe(5);
});

it('does not make unrelated subjects contend with one another after release', function (): void {
    $first = scalarRaceSubject(1);
    $second = scalarRaceSubject(2);
    seedScalarRaceSubject($first);
    seedScalarRaceSubject($second);

    $race = raceScalarFailures([$first, $second]);
    $counts = DB::table('auth_throttle_counters')
        ->orderBy('subject_digest')
        ->pluck('count')
        ->all();

    expect($race['exitCodes'])->toBe([0, 0], implode("\n", $race['outputs']))
        ->and($race['blockedWhileLocked'])->toBe([true, true])
        ->and($race['outputs'])->toBe(['ok', 'ok'])
        ->and($counts)->toBe([1, 1]);
});
