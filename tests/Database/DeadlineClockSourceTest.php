<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryOutcome;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\FixedClock;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Verification\IdentifierVerificationOutcome;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

/*
 * One clock per deadline.
 *
 * `DatabaseTime` exists because a security window written from the application
 * clock and evaluated against CURRENT_TIMESTAMP is nominally N seconds and
 * actually N seconds plus or minus the drift between two machines. The recovery
 * proof and the identifier verification both WRITE `expires_at` through
 * `DatabaseTime::deadline()` and then READ it against the PHP clock. The window
 * a user gets is the configured one only while the two machines agree.
 *
 * Both directions are covered, because they fail differently and only one of
 * them is loud:
 *
 *   - an application clock running BEHIND the database accepts a code the
 *     database already expired. Silent, and it is the security failure: a
 *     redeemed recovery proof opens grace, which is a password-reset capability.
 *   - an application clock running AHEAD refuses a code the database still
 *     considers live. An availability failure, which users report.
 *
 * What the fixture must rule out, and how:
 *
 *   - a fixture that never bound its clock would leave every test passing
 *     against the real one, so each skewed test asserts the binding took.
 *   - an implementation that reads `now()` or Carbon directly rather than the
 *     injected PSR clock would satisfy an injection-only skew while still
 *     comparing database time against application time, so BOTH clocks are
 *     moved together.
 *   - an implementation that simply weakens or drops the deadline would pass
 *     the skewed cases, so unskewed controls pin ordinary expiry.
 *   - an issuance that regressed to an application-derived deadline would
 *     survive tests that skew only at redemption, so one test per ceremony
 *     skews BEFORE issuing.
 *
 * Nothing asserts that the injected clock was CONSULTED. A correct fix stops
 * reading application time altogether, and such an assertion would reject it.
 *
 * Scope: these are the two ceremonies that write with DatabaseTime and read
 * with the PHP clock. Two adjacent crossings are deliberately not covered here
 * because their fixes differ in shape rather than in principle -- the OTP
 * driver's expiry check (#43) and the attempt TTL, which crosses the other way
 * by writing application time and reading database time (#44).
 */

const RECOVERY_PROOFS = 'auth_recovery_proofs';
const VERIFICATIONS = 'auth_identifier_verifications';

/** The database's current time, through the package's own accessor. */
function databaseNow(): DateTimeImmutable
{
    return app(DatabaseTime::class)->current();
}

/**
 * Skew the application's time N seconds from the database's, and return the
 * clock so a caller can assert the binding took.
 *
 * Carbon is moved with the PSR clock deliberately. Skewing only the injected
 * clock would let an implementation that calls `now()` directly pass every test
 * here while still comparing a database-written deadline against application
 * time -- the exact defect, wearing a different spelling.
 */
function skewClocks(int $seconds): FixedClock
{
    $instant = databaseNow()->modify(sprintf('%+d seconds', $seconds));
    $clock = new FixedClock($instant);

    app()->instance(ClockInterface::class, $clock);
    Carbon::setTestNow(Carbon::instance(\DateTime::createFromImmutable($instant)));

    app()->forgetInstance(CredentialRecovery::class);
    app()->forgetInstance(IdentifierVerifier::class);

    return $clock;
}

/** Both application clocks really are the skewed one. */
function assertApplicationTimeIsSkewed(FixedClock $clock): void
{
    expect(app(ClockInterface::class))->toBe($clock)
        ->and(Carbon::now()->getTimestamp())->toBe($clock->now()->getTimestamp());
}

afterEach(function (): void {
    Carbon::setTestNow();
});

/** The single issued row, so nothing here depends on a table-wide update. */
function soleRowId(string $table): int
{
    $ids = DB::table($table)->pluck('id')->all();

    expect($ids)->toHaveCount(1);

    return (int) stringValue($ids[0]);
}

/**
 * Move one row's deadline N seconds from the DATABASE's current time.
 *
 * Built from the package's own portable expression rather than a PHP timestamp:
 * writing the premise from the application clock would bake the very skew these
 * tests are about into the setup.
 */
function shiftDeadlineOnDatabaseClock(string $table, int $id, int $seconds): void
{
    $updated = DB::update(
        'update ' . $table . ' set expires_at = ' . DatabaseTime::deadlineSql(DB::connection()->getDriverName())
        . ' where id = ?',
        [$seconds, $id],
    );

    // The shift hit the row it named. Without this a mistyped table or a filter
    // that matched nothing would leave the original deadline in place and the
    // test would report on a premise it never established.
    expect($updated)->toBe(1);
}

function storedDeadline(string $table, int $id): DateTimeImmutable
{
    return new DateTimeImmutable(stringValue(DB::table($table)->where('id', $id)->value('expires_at')));
}

/** Whether the database itself still considers that row's deadline live. */
function liveOnDatabaseClock(string $table, int $id): bool
{
    return DB::table($table)->where('id', $id)->whereRaw('expires_at > CURRENT_TIMESTAMP')->exists();
}

/**
 * The premise, stated as an ordering rather than assumed: application time sits
 * before a deadline the database has nonetheless passed. That ordering is the
 * whole bug, and asserting it means a passing test cannot be one where the two
 * clocks happened to agree after all.
 */
function assertLaggingClockWouldAcceptTheExpiredDeadline(string $table, int $id, FixedClock $clock): void
{
    $deadline = storedDeadline($table, $id);

    expect($clock->now()->getTimestamp())->toBeLessThan($deadline->getTimestamp())
        ->and($deadline->getTimestamp())->toBeLessThan(databaseNow()->getTimestamp());
}

/* ---- recovery ---------------------------------------------------------- */

function recoveryFor(string $value = 'ada@acme.example'): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

/** A verified identifier with a password credential, ready to recover. */
function recoverableAccount(string $value = 'ada@acme.example', int $userId = 1): void
{
    AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => 'old-password']);
}

/** Issue a proof and recover the code the way production delivers it. */
function issuedRecoveryCode(string $value = 'ada@acme.example'): string
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    app(CredentialRecovery::class)->request(recoveryFor($value));

    foreach (DB::table('auth_recovery_proof_outbox')->pluck('opaque_id') as $opaqueId) {
        app(RecoveryProofOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

function graceIsOpenFor(string $host): bool
{
    return app(GraceGuard::class)->activeFor($host) instanceof AuthSession;
}

it('refuses a recovery code the database has expired, even when the app clock lags', function (): void {
    /*
     * The dangerous direction. A host whose application clock is an hour behind
     * the database keeps redeeming proofs the database expired an hour ago, and
     * nothing surfaces it, because a successful recovery looks like a
     * successful recovery.
     */
    recoverableAccount();
    $code = issuedRecoveryCode();
    $proof = soleRowId(RECOVERY_PROOFS);

    shiftDeadlineOnDatabaseClock(RECOVERY_PROOFS, $proof, -60);
    expect(liveOnDatabaseClock(RECOVERY_PROOFS, $proof))->toBeFalse();

    $clock = skewClocks(-3600);
    assertApplicationTimeIsSkewed($clock);
    assertLaggingClockWouldAcceptTheExpiredDeadline(RECOVERY_PROOFS, $proof, $clock);

    expect(app(CredentialRecovery::class)->redeem(recoveryFor(), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::Refused);

    /*
     * Refusing is not enough on its own: the capability must not exist and the
     * proof must remain unspent, or a later correct redemption has already been
     * consumed by this one.
     */
    expect(graceIsOpenFor('host-session-1'))->toBeFalse()
        ->and(DB::table(RECOVERY_PROOFS)->where('id', $proof)->value('consumed_at'))->toBeNull();
});

it('refuses a recovery code that expired seconds ago, not merely long ago', function (): void {
    /*
     * A large offset only proves rejection far past the deadline, so an
     * implementation that quietly extends the window -- a stray tolerance, a
     * unit confusion, a comparison against the wrong column -- survives it.
     * Five seconds is inside any such slack but still unambiguously expired,
     * including under PostgreSQL's rounded CURRENT_TIMESTAMP(0).
     */
    recoverableAccount();
    $code = issuedRecoveryCode();
    $proof = soleRowId(RECOVERY_PROOFS);

    shiftDeadlineOnDatabaseClock(RECOVERY_PROOFS, $proof, -5);
    expect(liveOnDatabaseClock(RECOVERY_PROOFS, $proof))->toBeFalse();

    expect(app(CredentialRecovery::class)->redeem(recoveryFor(), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::Refused);
});

it('still redeems a live recovery code when the app clock runs ahead', function (): void {
    /*
     * The other direction, and the reason the fix cannot be "compare against
     * something earlier". An application clock an hour fast refuses proofs the
     * database considers live, stranding users for a reason no log explains.
     */
    recoverableAccount();
    $code = issuedRecoveryCode();
    $proof = soleRowId(RECOVERY_PROOFS);

    expect(liveOnDatabaseClock(RECOVERY_PROOFS, $proof))->toBeTrue();

    $clock = skewClocks(3600);
    assertApplicationTimeIsSkewed($clock);

    expect(app(CredentialRecovery::class)->redeem(recoveryFor(), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);

    // The outcome is not the capability. Assert the thing the outcome claims.
    expect(graceIsOpenFor('host-session-1'))->toBeTrue()
        ->and(DB::table(RECOVERY_PROOFS)->where('id', $proof)->value('consumed_at'))->not->toBeNull();
});

it('issues a recovery deadline on the database clock even when the app clock lags', function (): void {
    /*
     * Every other test here skews AFTER issuance, so an issuance that regressed
     * to an application-derived deadline would pass all of them. Skewing first
     * makes the written value itself the subject: on the database clock the
     * proof is live, and on a lagging application clock it would already be
     * 3600 - 300 seconds stale.
     */
    recoverableAccount();

    $clock = skewClocks(-3600);
    assertApplicationTimeIsSkewed($clock);

    $code = issuedRecoveryCode();
    $proof = soleRowId(RECOVERY_PROOFS);

    expect(liveOnDatabaseClock(RECOVERY_PROOFS, $proof))->toBeTrue()
        ->and(storedDeadline(RECOVERY_PROOFS, $proof)->getTimestamp())
        ->toBeGreaterThan($clock->now()->getTimestamp());

    expect(app(CredentialRecovery::class)->redeem(recoveryFor(), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('refuses an expired recovery code while both clocks read the same instant', function (): void {
    /*
     * The control, and it BINDS agreement rather than assuming the test machine
     * happens to provide it. Without this the refusals above could come from a
     * broken fixture -- an unissued proof, an undelivered code, a shift that
     * matched nothing -- rather than from the deadline.
     */
    recoverableAccount();
    $code = issuedRecoveryCode();
    $proof = soleRowId(RECOVERY_PROOFS);

    shiftDeadlineOnDatabaseClock(RECOVERY_PROOFS, $proof, -60);

    $clock = skewClocks(0);
    assertApplicationTimeIsSkewed($clock);

    expect(app(CredentialRecovery::class)->redeem(recoveryFor(), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::Refused);
});

it('opens grace for a live recovery code while both clocks read the same instant', function (): void {
    // The control's other half: issuance and delivery are sound, so a refusal
    // above is attributable to the deadline alone.
    recoverableAccount();
    $code = issuedRecoveryCode();

    $clock = skewClocks(0);
    assertApplicationTimeIsSkewed($clock);

    expect(app(CredentialRecovery::class)->redeem(recoveryFor(), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

/* ---- identifier verification ------------------------------------------- */

function verificationFor(string $value = 'grace@acme.example'): IdentifierVerificationRequest
{
    return new IdentifierVerificationRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function unverifiedIdentifier(string $value = 'grace@acme.example', int $userId = 1): void
{
    AuthIdentifier::create(['user_id' => $userId, 'type' => 'email', 'value' => $value, 'verified_at' => null]);
}

/** Issue a verification and recover its code through the outbox worker. */
function issuedVerificationCode(string $value = 'grace@acme.example'): string
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    app(IdentifierVerifier::class)->request(verificationFor($value));

    foreach (DB::table('auth_identifier_verification_outbox')->pluck('opaque_id') as $opaqueId) {
        app(VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

function verifiedAtFor(string $value = 'grace@acme.example'): mixed
{
    return AuthIdentifier::query()->where('value', $value)->value('verified_at');
}

it('refuses a verification code the database has expired, even when the app clock lags', function (): void {
    /*
     * Verification sets verified_at, and a verified identifier is precisely what
     * recovery will later accept as a target. An expired code honoured here is
     * not a contained failure; it seeds the ceremony above it.
     */
    unverifiedIdentifier();
    $code = issuedVerificationCode();
    $verification = soleRowId(VERIFICATIONS);

    shiftDeadlineOnDatabaseClock(VERIFICATIONS, $verification, -60);
    expect(liveOnDatabaseClock(VERIFICATIONS, $verification))->toBeFalse();

    $clock = skewClocks(-3600);
    assertApplicationTimeIsSkewed($clock);
    assertLaggingClockWouldAcceptTheExpiredDeadline(VERIFICATIONS, $verification, $clock);

    expect(app(IdentifierVerifier::class)->redeem(verificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Refused);

    expect(verifiedAtFor())->toBeNull()
        ->and(DB::table(VERIFICATIONS)->where('id', $verification)->value('consumed_at'))->toBeNull();
});

it('refuses a verification code that expired seconds ago, not merely long ago', function (): void {
    unverifiedIdentifier();
    $code = issuedVerificationCode();
    $verification = soleRowId(VERIFICATIONS);

    shiftDeadlineOnDatabaseClock(VERIFICATIONS, $verification, -5);
    expect(liveOnDatabaseClock(VERIFICATIONS, $verification))->toBeFalse();

    expect(app(IdentifierVerifier::class)->redeem(verificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Refused);
});

it('still verifies with a live verification code when the app clock runs ahead', function (): void {
    unverifiedIdentifier();
    $code = issuedVerificationCode();
    $verification = soleRowId(VERIFICATIONS);

    expect(liveOnDatabaseClock(VERIFICATIONS, $verification))->toBeTrue();

    $clock = skewClocks(3600);
    assertApplicationTimeIsSkewed($clock);

    expect(app(IdentifierVerifier::class)->redeem(verificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Verified);

    expect(verifiedAtFor())->not->toBeNull()
        ->and(DB::table(VERIFICATIONS)->where('id', $verification)->value('consumed_at'))->not->toBeNull();
});

it('issues a verification deadline on the database clock even when the app clock lags', function (): void {
    unverifiedIdentifier();

    $clock = skewClocks(-3600);
    assertApplicationTimeIsSkewed($clock);

    $code = issuedVerificationCode();
    $verification = soleRowId(VERIFICATIONS);

    expect(liveOnDatabaseClock(VERIFICATIONS, $verification))->toBeTrue()
        ->and(storedDeadline(VERIFICATIONS, $verification)->getTimestamp())
        ->toBeGreaterThan($clock->now()->getTimestamp());

    expect(app(IdentifierVerifier::class)->redeem(verificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Verified);
});

it('refuses an expired verification code while both clocks read the same instant', function (): void {
    unverifiedIdentifier();
    $code = issuedVerificationCode();
    $verification = soleRowId(VERIFICATIONS);

    shiftDeadlineOnDatabaseClock(VERIFICATIONS, $verification, -60);

    $clock = skewClocks(0);
    assertApplicationTimeIsSkewed($clock);

    expect(app(IdentifierVerifier::class)->redeem(verificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Refused);
});

it('verifies a live verification code while both clocks read the same instant', function (): void {
    unverifiedIdentifier();
    $code = issuedVerificationCode();

    $clock = skewClocks(0);
    assertApplicationTimeIsSkewed($clock);

    expect(app(IdentifierVerifier::class)->redeem(verificationFor(), $code))
        ->toBe(IdentifierVerificationOutcome::Verified);
});
