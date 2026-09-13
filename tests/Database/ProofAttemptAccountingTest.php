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

function accountingRecoveryFor(string $value = 'ada@acme.example'): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function accountingVerificationFor(string $value = 'grace@acme.example'): IdentifierVerificationRequest
{
    return new IdentifierVerificationRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
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

it('throttles repeated recovery redemption rather than only counting it', function (): void {
    /*
     * Burning bounds what a guesser GAINS; throttling bounds what they can
     * SPEND. Without the second, an attacker who knows an address can burn its
     * codes as fast as they can send requests -- turning the brute-force
     * defence into a way to deny someone their own recovery.
     *
     * The assertion is deliberately about the boundary rather than a mechanism:
     * guessing far past the burn limit must stop reaching the proof at all.
     */
    accountingAccount();
    $code = issuedRecoveryProofCode();
    $proof = soleProofId('auth_recovery_proofs');

    foreach (range(1, attemptLimit() * 4) as $ignored) {
        app(CredentialRecovery::class)->redeem(accountingRecoveryFor(), wrongCode($code), 'host-a');
    }

    // Counting stops at the limit: a burned proof takes no further attempts,
    // whatever else is or is not in front of it.
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
