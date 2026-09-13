<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryOutcome;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;

/*
 * Issue #31 -- what happens when guesses arrive together.
 *
 * A PHP read-increment-write lets a burst of concurrent guesses all observe the
 * same count and collapse into one, which is the exact workload this boundary
 * exists to withstand; DatabaseAuthThrottleStore's challenge counter carries a
 * comment saying so. These tests are the reason that comment has to stay true
 * for proofs as well.
 *
 * DatabaseMigrations rather than RefreshDatabase: forked children cannot see an
 * uncommitted transaction, so every racing writer would work on an empty table
 * and the assertions would hold vacuously.
 *
 * THROTTLING IS MADE PERMISSIVE here, deliberately. With backoff in front, a
 * losing guess is refused before it reaches the counter -- which looks exactly
 * like a lost increment. Raising the thresholds keeps these tests about
 * accounting under contention, which is what they claim to measure; the
 * throttle's own behaviour is covered where it can be observed cleanly.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection its own.',
        );
    }

    if (! function_exists('pcntl_fork')) {
        $this->markTestSkipped('A genuine interleave needs pcntl_fork.');
    }

    /*
     * Make throttling permissive, and REBUILD the services that already read
     * it. ThrottleConfiguration is resolved eagerly at boot, so setting config
     * alone leaves the effective thresholds at their defaults and a refused
     * guess -- never reaching the counter -- looks exactly like a lost
     * increment, which is the one thing these tests must not confuse.
     *
     * Raised as far as the package ALLOWS rather than to an absurd number. It
     * refuses a lock_after above the fixed-boundary online-guess target derived
     * from the TOTP settings, which caps it at sixteen for the shipped defaults
     * -- a refusal worth respecting rather than working around. Sixteen is
     * comfortably above the handful of guesses any test here makes, which is
     * all these need.
     */
    Config::set('vouch.throttle.identifier.backoff_after', 15);
    Config::set('vouch.throttle.identifier.lock_after', 16);

    foreach ([
        \Fissible\Vouch\Throttle\ThrottleConfiguration::class,
        \Fissible\Vouch\Contracts\AuthThrottleStore::class,
        CredentialRecovery::class,
    ] as $service) {
        app()->forgetInstance($service);
    }

    // Asserted rather than assumed: a rebuild that silently failed would leave
    // every accounting race measuring the throttle instead.
    expect(app(\Fissible\Vouch\Throttle\ThrottleConfiguration::class)->backoffAfter)->toBe(15);
});

function guessRequest(): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: 'ada@acme.example',
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function guessableAccount(): void
{
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(1, ['password' => 'old-password']);
}

function guessLimit(): int
{
    return Config::integer('vouch.throttle.challenge.attempts');
}

/** Issue one proof and return its delivered code. */
function guessableProofCode(): string
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    app(CredentialRecovery::class)->request(guessRequest());

    foreach (DB::table('auth_recovery_proof_outbox')->whereNull('delivered_at')->pluck('opaque_id') as $opaqueId) {
        app(RecoveryProofOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

/**
 * Put the proof's counter at $attempts without going through redemption.
 *
 * Seeded rather than guessed up to, so a race can start one attempt below the
 * limit without the setup itself racing. Fails loudly when the column is
 * missing: SQLite resolves an unknown double-quoted identifier as a string
 * literal, so an update naming one silently affects nothing.
 */
function seedAttempts(int $id, int $attempts): void
{
    if (! Schema::hasColumn('auth_recovery_proofs', 'attempts')) {
        throw new RuntimeException('auth_recovery_proofs has no attempts column, so this premise cannot be set.');
    }

    $updated = DB::table('auth_recovery_proofs')->where('id', $id)->update(['attempts' => $attempts]);

    expect($updated)->toBe(1);
}

/** @return array{attempts: int, burned: bool, consumed: bool, superseded: bool} */
function guessState(int $id): array
{
    foreach (['attempts', 'burned_at', 'consumed_at', 'superseded_at'] as $column) {
        if (! Schema::hasColumn('auth_recovery_proofs', $column)) {
            throw new RuntimeException("auth_recovery_proofs has no {$column} column.");
        }
    }

    $row = requiredRow(DB::table('auth_recovery_proofs')->where('id', $id)->first());

    return [
        'attempts' => (int) stringValue($row->attempts),
        'burned' => $row->burned_at !== null,
        'consumed' => $row->consumed_at !== null,
        'superseded' => $row->superseded_at !== null,
    ];
}

/**
 * Submit $codes simultaneously from separate processes, released together.
 *
 * Forked children rather than sequential calls: the whole question is what
 * happens when two increments overlap, and one process cannot overlap itself.
 *
 * @param  list<string>  $codes
 * @return list<string>  each child's outcome name, or its exception class
 */
function raceGuesses(array $codes): array
{
    $directory = sys_get_temp_dir() . '/vouch-guess-race-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create the guess barrier directory.');
    }

    $release = $directory . '/release';
    $children = [];

    /*
     * disconnect(), not purge(). Purging removes the manager's connection
     * entirely, so already-resolved singletons -- the throttle store among them
     * -- keep the old object and end up writing through a different connection
     * than the transaction they were meant to join. Measured, that produced
     * SQLite lock failures rather than the race under test.
     */
    DB::disconnect();

    foreach ($codes as $index => $code) {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Could not fork a guessing child.');
        }

        if ($pid === 0) {
            $output = $directory . "/output-{$index}";

            $connection = DB::connection();

            try {
                $connection->getPdo();

                if ($connection->getDriverName() === 'sqlite') {
                    $connection->statement('PRAGMA busy_timeout = 5000');
                }

                file_put_contents($directory . "/database-{$index}", $connection->getDatabaseName());
                touch($directory . "/ready-{$index}");

                $deadline = microtime(true) + 10.0;

                while (! is_file($release)) {
                    if (microtime(true) >= $deadline) {
                        throw new RuntimeException('Timed out waiting for the guess release.');
                    }

                    usleep(500);
                }

                $outcome = app(CredentialRecovery::class)->redeem(guessRequest(), $code, "host-{$index}");
                file_put_contents($output, $outcome->name);
                exit(0);
            } catch (Throwable $exception) {
                /*
                 * Classified through the package's own measured classifier.
                 * "Any throw" accepts a programming error as honest
                 * contention, and SQLite reports the same SQLSTATE for a
                 * missing table as for a lock.
                 */
                $contended = $exception instanceof \Illuminate\Database\QueryException
                    && app(\Fissible\Vouch\Support\LockContention::class)->isVerified($connection, $exception);

                file_put_contents(
                    $output,
                    ($contended ? 'contention:' : 'error:') . $exception::class,
                );
                exit(1);
            }
        }

        $children[$index] = $pid;
    }

    $barrierDeadline = microtime(true) + 10.0;

    foreach (array_keys($children) as $index) {
        while (! is_file($directory . "/ready-{$index}")) {
            if (microtime(true) >= $barrierDeadline) {
                throw new RuntimeException('A guessing child never reached the barrier.');
            }

            usleep(500);
        }
    }

    $parentDatabase = DB::connection()->getDatabaseName();

    foreach (array_keys($children) as $index) {
        if ((string) file_get_contents($directory . "/database-{$index}") !== $parentDatabase) {
            throw new RuntimeException("Guessing child {$index} used a different database.");
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

/** A code that is definitely not the delivered one. */
function guessWrong(string $delivered, int $offset = 1): string
{
    $wrong = str_pad((string) (((int) $delivered + $offset) % 1_000_000), 6, '0', STR_PAD_LEFT);

    expect($wrong)->not->toBe($delivered);

    return $wrong;
}

it('loses no increment when two guesses arrive together', function (): void {
    /*
     * Starting two below the limit, two simultaneous misses must land the
     * counter exactly ON it. A read-increment-write collapses them into one,
     * leaving the proof one short and still usable -- which is the whole reason
     * the challenge counter increments inside its UPDATE.
     */
    guessableAccount();
    $code = guessableProofCode();
    $proof = soleRowId('auth_recovery_proofs');

    seedAttempts($proof, guessLimit() - 2);

    $reports = raceGuesses([guessWrong($code, 1), guessWrong($code, 2)]);

    foreach ($reports as $report) {
        expect($report)->toBe(CredentialRecoveryOutcome::Refused->name, "a guessing child failed: {$report}");
    }

    expect($reports)->toHaveCount(2);

    $state = guessState($proof);

    expect($state['attempts'])->toBe(guessLimit())
        ->and($state['burned'])->toBeTrue()
        ->and($state['consumed'])->toBeFalse()
        ->and($state['superseded'])->toBeFalse();
});

it('never counts past the limit when guesses pile up', function (): void {
    /*
     * Starting one below, four simultaneous misses. Exactly one may take the
     * counter to the limit; the rest must find a burned proof and do nothing.
     * Counting past it would mean the burn is advisory rather than terminal.
     */
    guessableAccount();
    $code = guessableProofCode();
    $proof = soleRowId('auth_recovery_proofs');

    seedAttempts($proof, guessLimit() - 1);

    $reports = raceGuesses([
        guessWrong($code, 1),
        guessWrong($code, 2),
        guessWrong($code, 3),
        guessWrong($code, 4),
    ]);

    // Reports are judged rather than discarded: a child that died of a
    // programming error is not a losing racer, and treating it as one would
    // let the count below be short for a reason nothing here would notice.
    foreach ($reports as $report) {
        expect(str_starts_with($report, 'error:'))->toBeFalse("a guessing child failed unrelated to contention: {$report}");
    }

    $state = guessState($proof);

    expect($state['attempts'])->toBe(guessLimit())
        ->and($state['burned'])->toBeTrue();

    // And it stays finished: later submissions, right or wrong, change nothing.
    app(CredentialRecovery::class)->redeem(guessRequest(), guessWrong($code, 9), 'host-late');
    expect(app(CredentialRecovery::class)->redeem(guessRequest(), $code, 'host-late-correct'))
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and(guessState($proof))->toBe($state)
        ->and(app(GraceGuard::class)->activeFor('host-late-correct'))->toBeNull();
});

it('resolves a correct code racing the final wrong one to a single outcome', function (): void {
    /*
     * Either may win, and the two endings are different but each must be whole.
     * If the correct code wins the proof is consumed and unburned; if the wrong
     * one wins the proof is burned and unconsumed and no grace exists anywhere.
     * What must never happen is both -- a consumed AND burned row, or a grace
     * opened against a proof that was simultaneously burned.
     */
    guessableAccount();
    $code = guessableProofCode();
    $proof = soleRowId('auth_recovery_proofs');

    seedAttempts($proof, guessLimit() - 1);

    $reports = raceGuesses([$code, guessWrong($code, 1)]);

    $state = guessState($proof);
    $graces = DB::table('auth_sessions')->whereNotNull('recovery_grace_expires_at')->count();

    expect($state['consumed'] && $state['burned'])->toBeFalse('the proof ended both redeemed and burned');

    if ($state['consumed']) {
        expect($state['attempts'])->toBe(guessLimit() - 1)
            ->and($graces)->toBe(1)
            ->and($reports)->toContain(CredentialRecoveryOutcome::GraceOpened->name);

        return;
    }

    expect($state['burned'])->toBeTrue()
        ->and($state['attempts'])->toBe(guessLimit())
        ->and($graces)->toBe(0);
});

it('keeps burning and superseding exclusive when issuance races the final guess', function (): void {
    /*
     * The two terminal writers meeting on one row. Issuing supersedes live
     * proofs; the limiting guess burns this one. Whichever commits first, the
     * row must carry exactly one ending -- and a burned proof must not then be
     * superseded, nor a superseded one burned.
     */
    guessableAccount();
    $code = guessableProofCode();
    $proof = soleRowId('auth_recovery_proofs');

    seedAttempts($proof, guessLimit() - 1);

    $directory = sys_get_temp_dir() . '/vouch-issue-guess-' . bin2hex(random_bytes(8));

    if (! mkdir($directory, 0700) && ! is_dir($directory)) {
        throw new RuntimeException('Could not create the barrier directory.');
    }

    $release = $directory . '/release';

    DB::disconnect();

    $pid = pcntl_fork();

    if ($pid === -1) {
        throw new RuntimeException('Could not fork the issuing child.');
    }

    if ($pid === 0) {
        $connection = DB::connection();

        try {
            $connection->getPdo();

            if ($connection->getDriverName() === 'sqlite') {
                $connection->statement('PRAGMA busy_timeout = 5000');
            }

            touch($directory . '/ready');

            $deadline = microtime(true) + 10.0;

            while (! is_file($release)) {
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Timed out waiting for release.');
                }

                usleep(500);
            }

            app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
            app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
            app(CredentialRecovery::class)->request(guessRequest());
            file_put_contents($directory . '/report', 'issued');
            exit(0);
        } catch (Throwable $exception) {
            // Reported rather than swallowed. A child that silently died of a
            // lock timeout would leave the parent asserting about a race that
            // only one side ever entered.
            $contended = $exception instanceof \Illuminate\Database\QueryException
                && app(\Fissible\Vouch\Support\LockContention::class)->isVerified($connection, $exception);

            file_put_contents($directory . '/report', ($contended ? 'contention:' : 'error:') . $exception::class);
            exit(1);
        }
    }

    $deadline = microtime(true) + 10.0;

    while (! is_file($directory . '/ready')) {
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('The issuing child never reached the barrier.');
        }

        usleep(500);
    }

    touch($release);

    app(CredentialRecovery::class)->redeem(guessRequest(), guessWrong($code, 1), 'host-a');

    pcntl_waitpid($pid, $status);

    $report = is_file($directory . '/report') ? (string) file_get_contents($directory . '/report') : 'missing';

    /*
     * The issuing side either won its write or lost to contention. Anything
     * else -- a timeout wearing a generic name, a programming error -- means
     * the race never happened and the end state below describes one writer.
     */
    expect($report === 'issued' || str_starts_with($report, 'contention:'))->toBeTrue(
        "the issuing child did not finish cleanly: {$report}",
    );

    $issued = $report === 'issued';

    $state = guessState($proof);

    // Exactly one ending on the contested row -- but only once BOTH writers
    // have actually acted. A child that lost to contention wrote nothing, so
    // the guess is the only terminal writer and the row may legitimately show
    // just the burn.
    $endings = array_filter([$state['burned'], $state['consumed'], $state['superseded']]);

    expect(count($endings))->toBe(1, 'the contested proof did not end exactly once');

    // Burned and superseded are the two that can collide here, and they are the
    // pair mutual exclusivity exists to keep apart.
    expect($state['burned'] && $state['superseded'])->toBeFalse('the proof ended both burned and superseded');

    if ($issued) {
        $newest = (int) stringValue(DB::table('auth_recovery_proofs')->orderByDesc('id')->value('id'));

        expect($newest)->not->toBe($proof);

        /*
         * The replacement's count depends on which side committed first, and
         * BOTH orderings are correct.
         *
         * If the guess landed first it was charged to the old proof and the
         * replacement is untouched. If issuance landed first, the guess found
         * the replacement -- selection is by identifier, not by row -- and
         * charging it there is exactly right. Requiring zero rejected the
         * second ordering, which a correct implementation produces whenever
         * issuance wins.
         *
         * What must hold either way is that the replacement carries no ending
         * and no more than the single guess this test made.
         */
        $replacement = guessState($newest);

        expect($replacement['attempts'])->toBeLessThanOrEqual(1)
            ->and($replacement['burned'])->toBeFalse()
            ->and($replacement['superseded'])->toBeFalse();

        /*
         * The replacement's code is generated during the race, so the guess
         * intended as wrong can collide with it -- once in a million, and then
         * legitimately redeeming it. Rather than tolerate a flake or weaken the
         * assertion, the collision is checked for exactly: consumption is only
         * acceptable if the submitted code really does match this row.
         */
        if ($replacement['consumed']) {
            $row = requiredRow(DB::table('auth_recovery_proofs')->where('id', $newest)->first());

            expect(Hash::check(guessWrong($code, 1), stringValue($row->code_hash)))
                ->toBeTrue('the replacement was consumed by a code that does not match it');
        }
    }
});
