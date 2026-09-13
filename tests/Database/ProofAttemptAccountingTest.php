<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryOutcome;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Tests\Support\ProofStateObserver;
use Fissible\Vouch\Verification\IdentifierVerificationOutcome;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/*
 * Issue #31 -- a delivered code gets a bounded number of guesses.
 *
 * Neither redemption path counted failures. A wrong code returned Refused and
 * left the proof live until it expired, so a six-digit code was guessable for
 * its whole window -- and a correct guess opens recovery grace, which leads to
 * a password reset. The package already solves this one layer away: OtpFactor
 * records each failed challenge attempt and the store consumes the challenge at
 * the limit, in a single atomic statement.
 *
 * The frozen invariants:
 *
 *   - failed redemption increments attempts atomically;
 *   - the attempt that reaches the limit sets burned_at in the SAME write;
 *   - burned proofs cannot redeem, even if otherwise unexpired;
 *   - terminal timestamps are mutually exclusive;
 *   - issuing a new proof supersedes older unconsumed proofs (#38, unchanged);
 *   - a throttle stays in front of redemption.
 *
 * THREE TERMINAL STATES, and keeping them apart is the point. consumed_at means
 * the holder redeemed it; superseded_at means a newer code replaced it;
 * burned_at means guessing exhausted it. Collapsing burning into consumption
 * would file a redemption that never happened and hide attack activity from
 * whoever reads these rows -- the same objection that gave supersession its own
 * column in #38.
 *
 * Mutual exclusivity has a consequence worth stating, because it is the easiest
 * thing to get wrong: issuing a new code must NOT stamp superseded_at on a proof
 * that is already burned or consumed. Supersession applies to live proofs only.
 *
 * The throttle in front matters for the opposite reason to burning. Burning
 * bounds what a guesser gains; throttling bounds what they can spend, which is
 * what keeps burning from becoming a way to deny a user their own recovery.
 */

function accountingRecoveryFor(string $value = 'ada@acme.example', string $ip = '203.0.113.10'): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: $ip,
    );
}

function accountingVerificationFor(string $value = 'grace@acme.example', string $ip = '203.0.113.10'): IdentifierVerificationRequest
{
    return new IdentifierVerificationRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: $ip,
    );
}

function accountingAccount(string $value = 'ada@acme.example', int $userId = 1): void
{
    AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => 'old-password']);
}

function accountingDelivery(): ArrayOtpDelivery
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    return $delivery;
}

function issuedRecoveryProofCode(string $value = 'ada@acme.example'): string
{
    $delivery = accountingDelivery();

    app(CredentialRecovery::class)->request(accountingRecoveryFor($value));

    foreach (DB::table('auth_recovery_proof_outbox')->whereNull('delivered_at')->pluck('opaque_id') as $opaqueId) {
        app(RecoveryProofOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

function issuedVerificationProofCode(string $value = 'grace@acme.example'): string
{
    $delivery = accountingDelivery();

    app(IdentifierVerifier::class)->request(accountingVerificationFor($value));

    foreach (DB::table('auth_identifier_verification_outbox')->whereNull('delivered_at')->pluck('opaque_id') as $opaqueId) {
        app(VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

/** A code that is definitely not the delivered one, and definitely six digits. */
function wrongCode(string $delivered): string
{
    $wrong = str_pad((string) (((int) $delivered + 1) % 1_000_000), 6, '0', STR_PAD_LEFT);

    expect($wrong)->not->toBe($delivered);

    return $wrong;
}

/**
 * Drop the throttle's accumulated state without touching any proof.
 *
 * Burning a proof takes a run of failures, and those failures legitimately
 * back the identifier off -- so a test that burns and then immediately uses a
 * replacement is asserting against a throttled caller and would reject a
 * correct implementation. Clearing between the two keeps such a test about
 * accounting, which is what it claims to measure.
 */
function clearThrottleState(): void
{
    foreach (['auth_throttle_counters', 'auth_throttle_locks', 'auth_throttle_tuples'] as $table) {
        DB::table($table)->delete();
    }
}

function attemptLimit(): int
{
    return Config::integer('vouch.throttle.challenge.attempts');
}

/**
 * Read a proof's accounting columns, failing loudly when they do not exist.
 *
 * SQLite resolves an unknown double-quoted identifier as a STRING LITERAL, so a
 * query naming a missing column returns something rather than erroring, and
 * these assertions would report on values the database never held.
 *
 * @return array{attempts: int, burned: bool, consumed: bool, superseded: bool}
 */
function proofAccounting(string $table, int $id): array
{
    foreach (['attempts', 'burned_at', 'consumed_at', 'superseded_at'] as $column) {
        if (! Schema::hasColumn($table, $column)) {
            throw new RuntimeException("{$table} has no {$column} column, so this reading means nothing.");
        }
    }

    $row = requiredRow(DB::table($table)->where('id', $id)->first());

    return [
        'attempts' => (int) stringValue($row->attempts),
        'burned' => $row->burned_at !== null,
        'consumed' => $row->consumed_at !== null,
        'superseded' => $row->superseded_at !== null,
    ];
}

function soleProofId(string $table): int
{
    return soleRowId($table);
}

/**
 * No row anywhere carries two terminal stamps.
 *
 * Asserted over every row of both tables rather than the one under test: the
 * states are written by different code paths, and the pairing that breaks is
 * usually the one a focused test was not looking at.
 */
function assertTerminalStatesAreExclusive(): void
{
    foreach (['auth_recovery_proofs', 'auth_identifier_verifications'] as $table) {
        foreach (DB::table($table)->get() as $row) {
            $stamped = array_filter([
                'consumed_at' => $row->consumed_at,
                'superseded_at' => $row->superseded_at,
                'burned_at' => $row->burned_at,
            ], static fn (mixed $value): bool => $value !== null);

            expect(count($stamped))->toBeLessThan(
                2,
                "{$table} row {$row->id} carries two terminal stamps: " . implode(', ', array_keys($stamped)),
            );
        }
    }
}

/* ---- recovery ----------------------------------------------------------- */

it('counts a failed recovery guess', function (): void {
    // The floor. Without a counter nothing else in this file can be true.
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a'))
        ->toBe(CredentialRecoveryOutcome::Refused);

    expect(proofAccounting('auth_recovery_proofs', $proof)['attempts'])->toBe(1);
});

it('leaves a recovery proof usable below the guess limit', function (): void {
    /*
     * Counting must not cost the holder their code. A user who fat-fingers a
     * digit and retries is the common case, and an implementation that burned
     * on the first miss would pass a test that only checked burning.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit() - 1) as $ignored) {
        expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a'))
            ->toBe(CredentialRecoveryOutcome::Refused);
    }

    $state = proofAccounting('auth_recovery_proofs', $proof);

    expect($state['attempts'])->toBe(attemptLimit() - 1)
        ->and($state['burned'])->toBeFalse();

    // And the real code still works, which is the half that matters to a user.
    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('burns a recovery proof on the guess that reaches the limit', function (): void {
    // The same write, not a later sweep: a burn that lands after the response
    // leaves a window in which the next guess still counts.
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    $state = proofAccounting('auth_recovery_proofs', $proof);

    expect($state['attempts'])->toBe(attemptLimit())
        ->and($state['burned'])->toBeTrue()
        ->and($state['consumed'])->toBeFalse()
        ->and($state['superseded'])->toBeFalse();

    assertTerminalStatesAreExclusive();
});

it('refuses the correct code once its recovery proof is burned', function (): void {
    /*
     * The whole point. The proof is unexpired, unconsumed and unsuperseded, and
     * the submitted code is the one that was delivered -- it must still refuse,
     * or burning is bookkeeping rather than a defence.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    expect(proofAccounting('auth_recovery_proofs', $proof)['burned'])->toBeTrue();

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::Refused);
});

it('does not count a correct recovery redemption as a failure', function (): void {
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-a'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);

    $state = proofAccounting('auth_recovery_proofs', $proof);

    expect($state['attempts'])->toBe(0)
        ->and($state['consumed'])->toBeTrue()
        ->and($state['burned'])->toBeFalse();

    assertTerminalStatesAreExclusive();
});

it('gives a newly issued recovery proof its own guess budget', function (): void {
    /*
     * Budgets belong to a code, not to an identifier. A user whose code was
     * burned -- by their own mistyping or by someone else's guessing -- must be
     * able to request another and use it.
     *
     * This is also where burning could have become a denial of recovery, so the
     * test is as much about the user's way out as about the accounting.
     */
    accountingAccount();
    $first = issuedRecoveryProofCode();

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($first), 'host-a');
    }

    clearThrottleState();

    $second = issuedRecoveryProofCode();
    $newest = (int) stringValue(DB::table('auth_recovery_proofs')->orderByDesc('id')->value('id'));

    expect(proofAccounting('auth_recovery_proofs', $newest)['attempts'])->toBe(0);

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $second, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('does not supersede a proof that is already burned', function (): void {
    /*
     * The mutual-exclusivity consequence that is easiest to miss. #38 supersedes
     * every prior unconsumed proof on issuance, and a burned proof is unconsumed
     * -- so the obvious predicate stamps superseded_at on top of burned_at and
     * the row ends up claiming two different endings.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $burned = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    expect(proofAccounting('auth_recovery_proofs', $burned)['burned'])->toBeTrue();

    issuedRecoveryProofCode();

    $state = proofAccounting('auth_recovery_proofs', $burned);

    expect($state['burned'])->toBeTrue()
        ->and($state['superseded'])->toBeFalse();

    assertTerminalStatesAreExclusive();
});

it('does not burn a proof that has already been superseded', function (): void {
    // The other direction: a superseded proof is out of play, and guessing at
    // it must not overwrite why it left.
    accountingAccount();
    $first = issuedRecoveryProofCode();
    $superseded = soleProofId('auth_recovery_proofs');

    issuedRecoveryProofCode();

    expect(proofAccounting('auth_recovery_proofs', $superseded)['superseded'])->toBeTrue();

    foreach (range(1, attemptLimit() * 2) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($first), 'host-a');
    }

    $state = proofAccounting('auth_recovery_proofs', $superseded);

    expect($state['superseded'])->toBeTrue()
        ->and($state['burned'])->toBeFalse();

    assertTerminalStatesAreExclusive();
});

/* ---- identifier verification -------------------------------------------- */

it('counts a failed verification guess', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();
    $proof = soleProofId('auth_identifier_verifications');

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), wrongCode($code)))
        ->toBe(IdentifierVerificationOutcome::Refused);

    expect(proofAccounting('auth_identifier_verifications', $proof)['attempts'])->toBe(1);
});

it('burns a verification proof on the guess that reaches the limit', function (): void {
    /*
     * Verification is a separate implementation, and every review of #38 found
     * it missing something recovery already had. It matters here because a
     * verified identifier is what recovery later accepts as a target.
     */
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();
    $proof = soleProofId('auth_identifier_verifications');

    foreach (range(1, attemptLimit()) as $ignored) {
        app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), wrongCode($code));
    }

    $state = proofAccounting('auth_identifier_verifications', $proof);

    expect($state['attempts'])->toBe(attemptLimit())
        ->and($state['burned'])->toBeTrue()
        ->and($state['consumed'])->toBeFalse();

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->toBeNull();

    assertTerminalStatesAreExclusive();
});

it('leaves a verification proof usable below the guess limit', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();

    foreach (range(1, attemptLimit() - 1) as $ignored) {
        app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), wrongCode($code));
    }

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Verified);
});

/* ---- decoys -------------------------------------------------------------- */

it('accounts a decoy ceremony exactly as it accounts a real one', function (): void {
    /*
     * Decoys exist so an unknown identifier costs what a known one costs. If
     * guessing against a decoy skipped the counter, the work would differ by
     * account existence on the one path an attacker can drive freely.
     *
     * State parity only, as elsewhere: this says nothing about latency, which
     * is the shape the enumeration threat actually takes.
     */
    accountingAccount('ada@acme.example', 1);

    $code = issuedRecoveryProofCode('ada@acme.example');
    app(CredentialRecovery::class)->redeem(accountingRecoveryFor('ada@acme.example'), wrongCode($code), 'host-a');

    $real = proofAccounting('auth_recovery_proofs', soleProofId('auth_recovery_proofs'));

    DB::table('auth_recovery_proof_outbox')->delete();
    DB::table('auth_recovery_proofs')->delete();

    accountingDelivery();
    app(CredentialRecovery::class)->request(accountingRecoveryFor('nobody@acme.example'));
    app(CredentialRecovery::class)->redeem(accountingRecoveryFor('nobody@acme.example'), '000000', 'host-b');

    $decoy = proofAccounting('auth_recovery_proofs', soleProofId('auth_recovery_proofs'));

    expect($real['attempts'])->toBe(1)
        ->and($decoy)->toBe($real);
});

/* ---- throttling in front of redemption ---------------------------------- */

it('does not increment recovery attempts after burning', function (): void {
    /*
     * Named for what it checks. Burning alone satisfies this, so it says
     * nothing about a throttle being in front of redemption -- the test below
     * covers that, by acting while the proof still has budget.
     *
     * It still earns its place: a burned proof must stop absorbing writes, or
     * the counter climbs forever on a row nobody can use.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit() * 4) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    expect(proofAccounting('auth_recovery_proofs', $proof)['attempts'])->toBe(attemptLimit());
});

it('limits recovery issuance the way verification already does', function (): void {
    /*
     * The compounding half of #31. IdentifierVerifier refuses issuance past its
     * ceremony limit; CredentialRecovery::request() had no throttle at all, so
     * a caller could mint codes indefinitely -- delivering mail each time and
     * handing a guesser a fresh window whenever the last one burned.
     */
    accountingAccount();
    accountingDelivery();

    $limit = Config::integer('vouch.throttle.challenge.issuances_per_identifier');

    foreach (range(1, $limit * 3) as $ignored) {
        app(CredentialRecovery::class)->request(accountingRecoveryFor());
    }

    // Refusal is silent, matching IdentifierVerifier: the count is the evidence.
    expect(DB::table('auth_recovery_proofs')->count())->toBeLessThanOrEqual($limit);
});

/**
 * Drive the shared recovery throttle into backoff for this identifier.
 *
 * Through the real store rather than by writing rows, so the precondition is
 * established the way production establishes it. Returns once the store itself
 * reports backoff, which is the only trustworthy signal that the setup worked.
 */
function backOffRecovery(string $value = 'ada@acme.example'): void
{
    $store = app(\Fissible\Vouch\Contracts\AuthThrottleStore::class);
    $subject = app(\Fissible\Vouch\Throttle\ThrottleKey::class)->recovery($value, null);

    foreach (range(1, 40) as $ignored) {
        if ($store->recordRecoveryFailure($subject)->decision === \Fissible\Vouch\Throttle\ThrottleDecision::BackedOff) {
            return;
        }
    }

    throw new RuntimeException('The recovery throttle never backed off, so this premise was never established.');
}

function recoveryIsBackedOff(string $value = 'ada@acme.example'): bool
{
    return app(\Fissible\Vouch\Contracts\AuthThrottleStore::class)->preflightShared(
        app(\Fissible\Vouch\Throttle\ThrottleKey::class)->recovery($value, null),
    )->decision === \Fissible\Vouch\Throttle\ThrottleDecision::BackedOff;
}

it('refuses recovery redemption while backed off, without spending the proof', function (): void {
    /*
     * The throttle in front, tested while the proof STILL HAS BUDGET -- which
     * is the only window where "throttled" and "burned and therefore inert"
     * look different from outside.
     *
     * Burning bounds what a guesser gains. Throttling bounds what they can
     * spend, and without it an attacker who knows an address can burn its codes
     * as fast as they can send guesses, turning the brute-force defence into a
     * way to deny someone their own recovery.
     *
     * A backed-off submission must leave no trace: no attempt counted, nothing
     * consumed, no grace opened. Counting it would let a throttled attacker
     * burn the proof anyway, one refused request at a time.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    backOffRecovery();
    expect(recoveryIsBackedOff())->toBeTrue();

    $before = proofAccounting('auth_recovery_proofs', $proof);

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a'))
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::Refused);

    $after = proofAccounting('auth_recovery_proofs', $proof);

    expect($after)->toBe($before)
        ->and($after['consumed'])->toBeFalse()
        ->and(app(\Fissible\Vouch\Recovery\GraceGuard::class)->activeFor('host-b'))->toBeNull();
});

it('redeems once the recovery backoff lapses', function (): void {
    /*
     * The other half, and the reason the test above is not simply "refuse
     * everything". Backoff has to END: an implementation that refuses forever
     * once throttled would pass the first test and lock users out permanently.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();

    backOffRecovery();
    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-a'))
        ->toBe(CredentialRecoveryOutcome::Refused);

    /*
     * Clear the throttle's own state without touching the proof, which stays
     * unexpired. The tables are named rather than guessed at, and the store is
     * asked afterwards whether the backoff really lifted -- clearing the wrong
     * ones would otherwise leave this test asserting against a still-throttled
     * identifier and passing for the wrong reason.
     */
    foreach (['auth_throttle_counters', 'auth_throttle_locks', 'auth_throttle_tuples'] as $table) {
        DB::table($table)->delete();
    }

    expect(recoveryIsBackedOff())->toBeFalse();

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('burns a recovery proof in the same write that reaches the limit', function (): void {
    /*
     * Final state cannot tell one statement from two. An implementation that
     * increments, returns to PHP, then updates burned_at passes every
     * end-state assertion in this file while leaving a window in which the row
     * reads attempts == limit and burned_at IS NULL -- and in that window
     * another guess still counts.
     *
     * So the row is observed BETWEEN statements rather than after them, in both
     * directions: increment-then-burn leaves it at the limit unburned, and
     * burn-then-increment leaves it burned while short of the limit.
     *
     * This DETECTS a split write on this connection. It does not prove a single
     * one -- an intermediate state visible here can be invisible to a competing
     * writer inside a transaction -- and that limit is recorded rather than
     * claimed away.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    // Fail with the same clear message as every other reading here when the
    // accounting columns are absent. Without this the observer simply records
    // nothing and the test reports "no samples", which describes the fixture
    // rather than the missing implementation.
    proofAccounting('auth_recovery_proofs', $proof);

    $observer = new ProofStateObserver('auth_recovery_proofs', $proof);
    DB::connection()->beforeExecuting(function () use ($observer): void {
        $observer->observe();
    });

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    // The observer actually observed, or the absence below proves nothing.
    expect($observer->seen)->not->toBe([]);

    expect($observer->inconsistentSamples(attemptLimit()))
        ->toBe([], 'the count and the burn were readable in disagreement');
});

it('counts a replacement recovery proof independently of the burned one', function (): void {
    /*
     * A counter keyed on the identifier rather than on the proof passes the
     * fresh-budget test: the replacement starts at zero because the old row is
     * where the count lives. It shows itself on the NEXT wrong guess, which
     * jumps straight to the limit and burns a code the user just received.
     *
     * So the replacement's progression is asserted step by step rather than
     * only at its start.
     */
    accountingAccount();
    $first = issuedRecoveryProofCode();

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($first), 'host-a');
    }

    clearThrottleState();

    $second = issuedRecoveryProofCode();
    $replacement = (int) stringValue(DB::table('auth_recovery_proofs')->orderByDesc('id')->value('id'));

    app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($second), 'host-b');

    $state = proofAccounting('auth_recovery_proofs', $replacement);

    expect($state['attempts'])->toBe(1)
        ->and($state['burned'])->toBeFalse();

    // And it still redeems, which an identifier-keyed counter would have denied.
    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $second, 'host-c'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('refuses a burned recovery proof that is demonstrably unexpired', function (): void {
    /*
     * "Burned" must not be satisfied by "expired". The refusal test elsewhere
     * describes an unexpired proof but never re-establishes that premise after
     * the burn, so an implementation that simply expired the row would pass it.
     *
     * Here the deadline is pushed well into the future on the DATABASE clock
     * AFTER burning, so expiry cannot be what does the refusing.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    shiftDeadlineOnDatabaseClock('auth_recovery_proofs', $proof, 3600);

    $live = DB::table('auth_recovery_proofs')->where('id', $proof)
        ->whereRaw('expires_at > CURRENT_TIMESTAMP')->exists();

    expect($live)->toBeTrue()
        ->and(proofAccounting('auth_recovery_proofs', $proof)['burned'])->toBeTrue();

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::Refused);
});

it('preserves a terminal recovery timestamp against later submissions', function (): void {
    /*
     * Exclusivity alone can be satisfied dishonestly: clearing burned_at while
     * setting consumed_at leaves exactly one stamp and falsifies the record.
     * A terminal row is finished, so its stamp and its count must not move
     * however many codes are thrown at it afterwards.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    $before = requiredRow(DB::table('auth_recovery_proofs')->where('id', $proof)->first());

    app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-b');
    app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-c');

    $after = requiredRow(DB::table('auth_recovery_proofs')->where('id', $proof)->first());

    expect($after->burned_at)->toBe($before->burned_at)
        ->and($after->consumed_at)->toBe($before->consumed_at)
        ->and($after->superseded_at)->toBe($before->superseded_at)
        ->and((int) stringValue($after->attempts))->toBe((int) stringValue($before->attempts));

    assertTerminalStatesAreExclusive();
});

it('preserves the failure count through a successful recovery redemption', function (): void {
    // The count is evidence, not scratch space: a success must not erase the
    // misses that preceded it, or the record cannot show a guessing attempt
    // that happened to end in the holder arriving first.
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit() - 1) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);

    $state = proofAccounting('auth_recovery_proofs', $proof);

    expect($state['attempts'])->toBe(attemptLimit() - 1)
        ->and($state['consumed'])->toBeTrue()
        ->and($state['burned'])->toBeFalse();
});

it('keeps guess budgets separate for two identifiers', function (): void {
    // A counter shared across unrelated proofs would let one address's guessing
    // burn another's code -- reachable by anyone who knows both addresses.
    accountingAccount('ada@acme.example', 1);
    accountingAccount('bob@acme.example', 2);

    $ada = issuedRecoveryProofCode('ada@acme.example');
    $bob = issuedRecoveryProofCode('bob@acme.example');

    foreach (range(1, attemptLimit()) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor('ada@acme.example'), wrongCode($ada), 'host-a');
    }

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor('bob@acme.example'), $bob, 'host-b'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

/**
 * A wrong code that differs from every other guess in the same test.
 *
 * Repeating one wrong value is the unrealistic case: an attacker submits a
 * DIFFERENT code each time. A counter that resets whenever the submitted value
 * changes satisfies every same-code test and never burns anything.
 */
function distinctWrongCode(string $delivered, int $nth): string
{
    $wrong = str_pad((string) (((int) $delivered + $nth) % 1_000_000), 6, '0', STR_PAD_LEFT);

    return $wrong === $delivered ? distinctWrongCode($delivered, $nth + 1) : $wrong;
}

it('burns a recovery proof on distinct wrong guesses, not just repeated ones', function (): void {
    /*
     * The shape a real attack takes, and the one every other test here missed:
     * each guess is a different six-digit code.
     *
     * A counter that resets when the submitted value changes passes the whole
     * rest of this file. Measured against such an implementation, a hundred
     * distinct guesses left attempts at one and the proof unburned, after which
     * the delivered code still worked.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    $submitted = [];

    foreach (range(1, attemptLimit()) as $nth) {
        $guess = distinctWrongCode($code, $nth);
        $submitted[] = $guess;

        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $guess, "host-{$nth}");
    }

    // Every guess really was different, or this proves nothing beyond the
    // same-code case already covered.
    expect(count(array_unique($submitted)))->toBe(attemptLimit());

    $state = proofAccounting('auth_recovery_proofs', $proof);

    expect($state['attempts'])->toBe(attemptLimit())
        ->and($state['burned'])->toBeTrue();

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-after'))
        ->toBe(CredentialRecoveryOutcome::Refused);
});

it('burns a verification proof on distinct wrong guesses, not just repeated ones', function (): void {
    // The same survivor in the other ceremony, which is where it was actually
    // demonstrated.
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();
    $proof = soleProofId('auth_identifier_verifications');

    $submitted = [];

    foreach (range(1, attemptLimit()) as $nth) {
        $guess = distinctWrongCode($code, $nth);
        $submitted[] = $guess;

        app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $guess);
    }

    expect(count(array_unique($submitted)))->toBe(attemptLimit());

    $state = proofAccounting('auth_identifier_verifications', $proof);

    expect($state['attempts'])->toBe(attemptLimit())
        ->and($state['burned'])->toBeTrue();

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->toBeNull();
});

it('counts distinct wrong guesses one at a time', function (): void {
    /*
     * Progression, not just the endpoint. A reset-on-change counter reaches the
     * limit eventually if something else also increments, so the count is read
     * after every guess rather than only at the end.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit() - 1) as $nth) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), distinctWrongCode($code, $nth), 'host-a');

        expect(proofAccounting('auth_recovery_proofs', $proof)['attempts'])->toBe($nth);
    }
});

it('refuses a burned verification proof that is demonstrably unexpired', function (): void {
    // Expiry substitution, for the ceremony that did not have this guard.
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();
    $proof = soleProofId('auth_identifier_verifications');

    foreach (range(1, attemptLimit()) as $nth) {
        app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), distinctWrongCode($code, $nth));
    }

    shiftDeadlineOnDatabaseClock('auth_identifier_verifications', $proof, 3600);

    expect(DB::table('auth_identifier_verifications')->where('id', $proof)
        ->whereRaw('expires_at > CURRENT_TIMESTAMP')->exists())->toBeTrue()
        ->and(proofAccounting('auth_identifier_verifications', $proof)['burned'])->toBeTrue();

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Refused);
});

it('preserves a terminal verification timestamp against later submissions', function (): void {
    // History preservation for the other ceremony.
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();
    $proof = soleProofId('auth_identifier_verifications');

    foreach (range(1, attemptLimit()) as $nth) {
        app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), distinctWrongCode($code, $nth));
    }

    $before = requiredRow(DB::table('auth_identifier_verifications')->where('id', $proof)->first());

    app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), distinctWrongCode($code, 99));
    app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $code);

    $after = requiredRow(DB::table('auth_identifier_verifications')->where('id', $proof)->first());

    expect($after->burned_at)->toBe($before->burned_at)
        ->and($after->consumed_at)->toBe($before->consumed_at)
        ->and($after->superseded_at)->toBe($before->superseded_at)
        ->and((int) stringValue($after->attempts))->toBe((int) stringValue($before->attempts));

    assertTerminalStatesAreExclusive();
});

it('counts a replacement verification proof independently of the burned one', function (): void {
    // Identifier-keyed counting, for the ceremony where the survivor was found.
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $first = issuedVerificationProofCode();

    foreach (range(1, attemptLimit()) as $nth) {
        app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), distinctWrongCode($first, $nth));
    }

    clearThrottleState();

    $second = issuedVerificationProofCode();
    $replacement = (int) stringValue(DB::table('auth_identifier_verifications')->orderByDesc('id')->value('id'));

    app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), distinctWrongCode($second, 1));

    expect(proofAccounting('auth_identifier_verifications', $replacement)['attempts'])->toBe(1);

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $second))
        ->toBe(IdentifierVerificationOutcome::Verified);
});

it('preserves the failure count through a successful verification', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();
    $proof = soleProofId('auth_identifier_verifications');

    foreach (range(1, attemptLimit() - 1) as $nth) {
        app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), distinctWrongCode($code, $nth));
    }

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Verified);

    $state = proofAccounting('auth_identifier_verifications', $proof);

    expect($state['attempts'])->toBe(attemptLimit() - 1)
        ->and($state['consumed'])->toBeTrue()
        ->and($state['burned'])->toBeFalse();
});

it('counts distinct recovery guesses arriving from alternating addresses', function (): void {
    /*
     * The budget belongs to the PROOF, not to whoever is asking. A counter that
     * resets when the source address changes passes every test that guesses
     * from one IP -- and measured against such an implementation, a hundred
     * guesses alternating between two addresses left attempts at one, the proof
     * unburned, and the delivered code still working.
     *
     * Rotating source addresses is the cheapest thing an attacker can do.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    $addresses = ['203.0.113.10', '198.51.100.7'];

    foreach (range(1, attemptLimit()) as $nth) {
        app(CredentialRecovery::class)->redeem(
            accountingRecoveryFor('ada@acme.example', $addresses[$nth % 2]),
            distinctWrongCode($code, $nth),
            "host-{$nth}",
        );
    }

    $state = proofAccounting('auth_recovery_proofs', $proof);

    expect($state['attempts'])->toBe(attemptLimit())
        ->and($state['burned'])->toBeTrue();

    expect(app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), $code, 'host-after'))
        ->toBe(CredentialRecoveryOutcome::Refused);
});

it('counts distinct verification guesses arriving from alternating addresses', function (): void {
    // The ceremony the survivor was demonstrated against.
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    $code = issuedVerificationProofCode();
    $proof = soleProofId('auth_identifier_verifications');

    $addresses = ['203.0.113.10', '198.51.100.7'];

    foreach (range(1, attemptLimit()) as $nth) {
        app(IdentifierVerifier::class)->redeem(
            accountingVerificationFor('grace@acme.example', $addresses[$nth % 2]),
            distinctWrongCode($code, $nth),
        );
    }

    $state = proofAccounting('auth_identifier_verifications', $proof);

    expect($state['attempts'])->toBe(attemptLimit())
        ->and($state['burned'])->toBeTrue();

    expect(app(IdentifierVerifier::class)->redeem(accountingVerificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->toBeNull();
});
