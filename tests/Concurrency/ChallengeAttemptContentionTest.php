<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\DatabaseAttemptStore;
use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('The challenge-attempt contention proof requires pcntl_fork.');
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'The challenge-attempt contention proof needs two processes on one file-backed database.',
        );
    }
});

/** @return array{AuthAttempt, AuthChallenge} */
function challengeAttemptRaceFixture(int $attempts): array
{
    $attempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'bound_context' => str_repeat('r', 64),
        'expires_at' => now()->addMinutes(10),
    ]);
    $challengeId = DB::table('auth_challenges')->insertGetId([
        'attempt_id' => $attempt->id,
        'factor_type' => 'email_otp',
        'code_hash' => 'race-does-not-compare-the-code',
        'attempts' => $attempts,
        'expires_at' => now()->addMinutes(5),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    return [$attempt->refresh(), AuthChallenge::findOrFail($challengeId)];
}

/**
 * Release two real database peers against one row already locked by the parent.
 * Absence of both output files before release proves neither child completed
 * outside the contested interval.
 *
 * @param list<'wrong'|'correct'> $operations
 * @return array{blocked: list<bool>, results: list<string>}
 */
function raceChallengeAttempts(
    AuthAttempt $attempt,
    AuthChallenge $challenge,
    array $operations,
): array {
    $directory = sys_get_temp_dir() . '/vouch-challenge-race-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create challenge contention barrier directory.');
    }

    $release = $directory . '/release';
    $children = [];
    $parent = null;
    $sqliteImmediate = false;
    $blocked = [];

    DB::purge();

    try {
        foreach ($operations as $index => $operation) {
            $pid = pcntl_fork();

            if ($pid === -1) {
                throw new RuntimeException('Could not fork challenge contention child.');
            }

            if ($pid === 0) {
                $ready = $directory . "/ready-{$index}";
                $started = $directory . "/started-{$index}";
                $output = $directory . "/output-{$index}";

                try {
                    $connection = DB::connection();
                    $connection->getPdo();

                    if ($connection->getDriverName() === 'sqlite') {
                        $connection->statement('PRAGMA busy_timeout = 5000');
                    }

                    touch($ready);
                    $deadline = microtime(true) + 10.0;

                    while (! is_file($release)) {
                        if (microtime(true) >= $deadline) {
                            throw new RuntimeException('Timed out waiting for challenge race release.');
                        }

                        usleep(1_000);
                    }

                    touch($started);

                    if ($operation === 'wrong') {
                        $store = new DatabaseAuthThrottleStore(
                            $connection,
                            new DatabaseTime($connection),
                            app(ThrottleConfiguration::class),
                        );
                        $result = $store->recordChallengeFailure($challenge->id)->name;
                    } else {
                        $storedAttempt = AuthAttempt::query()->findOrFail($attempt->id);
                        $store = new DatabaseAttemptStore($connection, new TransitionRules());
                        $result = $store->transition(
                            $storedAttempt,
                            AttemptState::FactorSatisfied,
                            new ConsumeChallenge($challenge->id, $attempt->id),
                        )->value;
                    }

                    file_put_contents($output, $result);
                    exit(0);
                } catch (Throwable $exception) {
                    file_put_contents($output, $exception::class . ': ' . $exception->getMessage());
                    exit(1);
                }
            }

            $children[$index] = $pid;
        }

        $deadline = microtime(true) + 10.0;

        foreach (array_keys($operations) as $index) {
            while (! is_file($directory . "/ready-{$index}")) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('A challenge race child did not reach the ready barrier.');
                }

                usleep(1_000);
            }
        }

        $parent = DB::connection();
        $sqliteImmediate = $parent->getDriverName() === 'sqlite';

        if ($sqliteImmediate) {
            $parent->statement('BEGIN IMMEDIATE');
            $parent->table('auth_challenges')
                ->where('id', $challenge->id)
                ->update([
                    'updated_at' => new \Illuminate\Database\Query\Expression(
                        "datetime(CURRENT_TIMESTAMP, '+1 second')",
                    ),
                ]);
        } else {
            $parent->beginTransaction();
            $locked = $parent->table('auth_challenges')
                ->where('id', $challenge->id)
                ->lockForUpdate()
                ->first();

            if ($locked === null) {
                throw new RuntimeException('The parent did not lock the challenge row.');
            }
        }

        touch($release);

        foreach (array_keys($operations) as $index) {
            while (! is_file($directory . "/started-{$index}")) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('A challenge race child did not start its store call.');
                }

                usleep(1_000);
            }
        }

        usleep(200_000);

        foreach (array_keys($operations) as $index) {
            $blocked[] = ! is_file($directory . "/output-{$index}");
        }

        if ($sqliteImmediate) {
            $parent->statement('COMMIT');
        } else {
            $parent->commit();
        }

        $results = [];

        foreach ($children as $index => $pid) {
            pcntl_waitpid($pid, $status);
            $output = (string) file_get_contents($directory . "/output-{$index}");

            if (pcntl_wexitstatus($status) !== 0) {
                throw new RuntimeException("Challenge race child {$index} failed: {$output}");
            }

            $results[] = $output;
        }

        return ['blocked' => $blocked, 'results' => $results];
    } finally {
        touch($release);

        if ($parent !== null && $sqliteImmediate && $parent->getPdo()->inTransaction()) {
            $parent->statement('ROLLBACK');
        } elseif ($parent !== null && $parent->transactionLevel() > 0) {
            $parent->rollBack();
        }

        foreach ($children as $pid) {
            $waited = pcntl_waitpid($pid, $status, WNOHANG);

            if ($waited === 0) {
                posix_kill($pid, SIGTERM);
                pcntl_waitpid($pid, $status);
            }
        }

        foreach (glob($directory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($directory);
        DB::purge();
    }
}

it('does not collapse two simultaneous wrong guesses at the invalidation boundary', function (): void {
    [$attempt, $challenge] = challengeAttemptRaceFixture(attempts: 3);

    $race = raceChallengeAttempts($attempt, $challenge, ['wrong', 'wrong']);
    $results = $race['results'];
    sort($results);
    $stored = AuthChallenge::findOrFail($challenge->id);

    expect($race['blocked'])->toBe([true, true])
        ->and($results)->toBe(['Invalidated', 'Remaining'])
        ->and($stored->attempts)->toBe(5)
        ->and($stored->consumed_at)->not->toBeNull();
});

it('makes the fifth wrong guess and a correct consume mutually exclusive', function (): void {
    [$attempt, $challenge] = challengeAttemptRaceFixture(attempts: 4);

    $race = raceChallengeAttempts($attempt, $challenge, ['wrong', 'correct']);
    $results = $race['results'];
    sort($results);
    $storedChallenge = AuthChallenge::findOrFail($challenge->id);
    $storedAttempt = AuthAttempt::findOrFail($attempt->id);

    $wrongWon = $results === ['Invalidated', 'challenge_already_consumed'];
    $correctWon = $results === ['Consumed', 'succeeded'];

    expect($race['blocked'])->toBe([true, true])
        ->and($wrongWon || $correctWon)->toBeTrue()
        ->and($storedChallenge->consumed_at)->not->toBeNull()
        ->and($storedChallenge->attempts)->toBe($wrongWon ? 5 : 4)
        ->and($storedAttempt->state)->toBe(
            $wrongWon ? AttemptState::FactorPending : AttemptState::FactorSatisfied,
        )
        ->and(DB::table('auth_throttle_locks')->count())->toBe(0)
        ->and(DB::table('auth_throttle_counters')->count())->toBe(0);
});
