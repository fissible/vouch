<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Support\IssuanceLockBucket;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

/*
 * #46, the half the sequential tests cannot reach.
 *
 * False sharing is accepted: two unrelated identifiers may land in one bucket
 * and serialize against each other. Sequentially that is invisible, because
 * nothing contends -- IssuanceLockCapacityTest issues for both addresses one
 * after the other and the mutex is free every time.
 *
 * What only a race can show is what the LOSER does. An implementation that
 * treats bucket contention as "somebody else is already issuing for this scope"
 * and returns without writing satisfies every sequential assertion AND
 * ProofIssuanceContentionTest, whose invariant is that exactly ONE live proof
 * survives -- true of one identifier, and equally true of two identifiers when
 * the second one silently lost its issuance. Measured on PostgreSQL: that mutant
 * passed all 27 capacity tests and all four contention bodies, and only this
 * file caught it.
 *
 * THE INVARIANT IS CONDITIONAL, and that is not a weakening. A writer is allowed
 * to lose to the database -- on SQLite it usually does, because lockForUpdate is
 * a no-op there and the whole file locks, so a second writer gets SQLITE_BUSY
 * that no busy_timeout can wait out. Measured: an unconditional "both addresses
 * end with a proof" failed roughly two runs in five on SQLite for that reason
 * alone. What is NOT allowed is returning normally having written nothing: a
 * caller who was told the request succeeded must have a proof. So each child's
 * own report decides what its address must show.
 *
 * No wall-clock assertion. "It cost latency" is only measurable against a
 * threshold, which is the flakiness class #43 and #44 already paid for.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection '
            . 'its own, so these would pass without racing.',
        );
    }

    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('A genuine interleave needs pcntl_fork.');
    }
});

/**
 * Two distinct addresses whose canonical forms share one mutex bucket.
 *
 * Named apart from IssuanceLockCapacityTest's collidingPair(): a helper two
 * files need belongs in tests/Pest.php, and a duplicate global function name
 * fatals the whole suite. Move both there if a third file ever wants one.
 *
 * @return array{string, string}
 */
function bucketSharingAddresses(string $ceremony): array
{
    $seen = [];

    for ($i = 0; $i < 3000; $i++) {
        $candidate = sprintf('shared-%d@acme.example', $i);
        $bucket = IssuanceLockBucket::for($ceremony, 'email', $candidate);

        if (isset($seen[$bucket])) {
            return [$seen[$bucket], $candidate];
        }

        $seen[$bucket] = $candidate;
    }

    throw new RuntimeException('No two probed identifiers shared a bucket.');
}

function sharedBucketDelivery(): void
{
    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
}

function sharedBucketAccount(string $value, int $userId): void
{
    AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

/**
 * Drop the throttle's accumulated state, in the PARENT only.
 *
 * Never inside a child: a child deleting throttle rows while a sibling is
 * mid-request removes the sibling's counter and tuple, and the refusal that
 * follows reads exactly like the mutex defect this file exists to catch.
 */
function clearSharedBucketThrottle(): void
{
    foreach (['auth_throttle_counters', 'auth_throttle_locks', 'auth_throttle_tuples'] as $table) {
        DB::table($table)->delete();
    }
}

function sharedBucketIssue(string $ceremony, string $value): void
{
    $ceremony === 'recovery'
        ? app(CredentialRecovery::class)->request(new CredentialRecoveryRequest(
            type: 'email',
            submittedIdentifier: $value,
            tenantId: null,
            clientIp: '203.0.113.10',
        ))
        : app(IdentifierVerifier::class)->request(new IdentifierVerificationRequest(
            type: 'email',
            submittedIdentifier: $value,
            tenantId: null,
            clientIp: '203.0.113.10',
        ));
}

/**
 * Race one issuance per address, from separate processes, released together.
 *
 * Forked children rather than two calls on one stack, for the reason
 * ProofIssuanceContentionTest states: request() resolves its outbox from the
 * container bound to the default connection, so naming a second connection in
 * one process still runs both calls on one handle.
 *
 * @param  list<string>  $addresses  one child per entry
 * @return list<string> what each child reported, in the same order
 */
function raceSharedBucketIssuance(string $ceremony, array $addresses): array
{
    $directory = sys_get_temp_dir() . '/vouch-shared-bucket-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create the barrier directory.');
    }

    $release = $directory . '/release';
    $children = [];

    // SQLite connections are not fork-safe even if the child purges its
    // inherited PDO. Close the seed connection before forking.
    DB::purge();

    foreach ($addresses as $index => $address) {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Could not fork a child.');
        }

        if ($pid === 0) {
            $output = $directory . "/output-{$index}";
            $connection = DB::connection();

            try {
                $connection->getPdo();

                if ($connection->getDriverName() === 'sqlite') {
                    $connection->statement('PRAGMA busy_timeout = 10000');
                }

                file_put_contents($directory . "/database-{$index}", $connection->getDatabaseName());
                sharedBucketDelivery();
                touch($directory . "/ready-{$index}");

                $deadline = microtime(true) + 10.0;

                while (! is_file($release)) {
                    if (microtime(true) >= $deadline) {
                        throw new RuntimeException('Timed out waiting for the release.');
                    }

                    usleep(1_000);
                }

                sharedBucketIssue($ceremony, $address);

                // "returned", not "issued": the parent counts the rows. What
                // matters is that a child which returned normally has one.
                file_put_contents($output, 'returned');
                exit(0);
            } catch (Throwable $exception) {
                file_put_contents(
                    $output,
                    (isContentionFailure($connection, $exception) ? 'contention|' : 'error|')
                    . $exception::class . '|' . $exception->getMessage(),
                );
                exit(1);
            }
        }

        $children[$index] = $pid;
    }

    $barrierDeadline = microtime(true) + 15.0;

    foreach (array_keys($children) as $index) {
        while (! is_file($directory . "/ready-{$index}")) {
            if (microtime(true) >= $barrierDeadline) {
                throw new RuntimeException('A child never reached the barrier.');
            }

            usleep(1_000);
        }
    }

    $parentDatabase = DB::connection()->getDatabaseName();

    foreach (array_keys($children) as $index) {
        // Children racing on separate databases would contend for nothing.
        if ((string) file_get_contents($directory . "/database-{$index}") !== $parentDatabase) {
            throw new RuntimeException("Child {$index} used a different database.");
        }
    }

    touch($release);

    $reports = [];

    foreach ($children as $index => $pid) {
        pcntl_waitpid($pid, $status);
        $reports[] = (string) file_get_contents($directory . "/output-{$index}");
    }

    return $reports;
}

it('never tells one identifier it issued while the other held the bucket', function (string $ceremony): void {
    sharedBucketDelivery();
    [$first, $second] = bucketSharingAddresses($ceremony);

    sharedBucketAccount($first, 1);
    sharedBucketAccount($second, 2);

    $table = $ceremony === 'recovery' ? 'auth_recovery_proofs' : 'auth_identifier_verifications';
    $addresses = [$first, $second];

    clearSharedBucketThrottle();

    $reports = raceSharedBucketIssuance($ceremony, $addresses);

    /*
     * No child may have crashed. A loser is allowed to lose to the database or
     * to return after rolling back; it is not allowed to raise anything else.
     */
    foreach ($reports as $report) {
        expect(str_starts_with($report, 'error|'))->toBeFalse('a racing writer crashed: ' . $report);
    }

    /*
     * THE POSITIVE CONTROL, and the reason the conditional assertion below is
     * not vacuous: a run in which every child lost proves nothing, and would
     * otherwise pass with a mutex that refuses everybody.
     */
    expect(in_array('returned', $reports, true))
        ->toBeTrue('no racing writer completed: ' . implode(' / ', $reports));

    foreach ($addresses as $index => $address) {
        $live = DB::table($table)->where('identifier_value', $address)
            ->whereNull('superseded_at')->whereNull('consumed_at')->whereNull('burned_at')
            ->count();

        /*
         * A child that returned normally told its caller the request succeeded,
         * so that address must hold a live proof. Sharing a bucket with somebody
         * else is a latency cost; it must never turn into a silently swallowed
         * issuance.
         */
        $reports[$index] === 'returned'
            ? expect($live)->toBe(1, sprintf('%s returned but has %d live proofs', $address, $live))
            : expect($live)->toBe(0, sprintf('%s lost the race but has %d live proofs', $address, $live));
    }

    // And no state crossed: nothing was written for any other identifier.
    expect(DB::table($table)->whereNotIn('identifier_value', $addresses)->count())->toBe(0);
})->with(['recovery', 'verification']);
