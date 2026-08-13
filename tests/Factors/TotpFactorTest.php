<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use OTPHP\TOTP;

uses(RefreshDatabase::class);

const TOTP_PERIOD = 30;

function totpFactor(): TotpFactor
{
    return app(TotpFactor::class);
}

/**
 * Narrows $result->mutations[0] to AdvanceCredentialTimestep for PHPStan via a
 * real instanceof check — SingleUseMutation doesn't declare ->timestep — and
 * fails the test loudly rather than silently if the shape is ever wrong.
 * Mirrors the isSatisfied() narrowing pattern used in RecoveryCodeFactorTest.
 */
function timestepOf(FactorResult $result): int
{
    $mutation = $result->mutations[0] ?? null;

    if (! $mutation instanceof AdvanceCredentialTimestep) {
        throw new RuntimeException('Expected an AdvanceCredentialTimestep mutation.');
    }

    return $mutation->timestep;
}

function totpAttempt(?int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => $userId,
        'bound_context' => 'sess-1',
        'expires_at' => now()->addMinutes(10),
    ]);
}

/** Enrolls and returns the raw base32 seed, read out of the encrypted column. */
function enrollTotp(int $userId = 7): string
{
    totpFactor()->enroll($userId, ['label' => 'ada@acme.example']);

    return (string) AuthCredential::where('user_id', $userId)->where('type', 'totp')->firstOrFail()->secret;
}

function codeAt(string $secret, int $timestamp): string
{
    return codeAtWith($secret, $timestamp, TOTP_PERIOD, 6);
}

/**
 * Like codeAt(), but for a non-default period/digits — used to generate codes
 * against a TotpFactor constructed directly with non-default configuration,
 * since the container-bound totpFactor() only ever exercises config defaults.
 */
function codeAtWith(string $secret, int $timestamp, int $period, int $digits): string
{
    if ($secret === '') {
        throw new RuntimeException('codeAtWith() requires a non-empty secret.');
    }

    // TOTP::at() takes 0|positive-int; every timestamp this suite passes is
    // already non-negative, so the floor is a type narrowing, not a behaviour
    // change.
    $timestamp = max(0, $timestamp);

    $totp = TOTP::createFromSecret($secret, new \Fissible\Vouch\Support\SystemClock());
    $totp->setPeriod($period);
    $totp->setDigits($digits);

    return $totp->at($timestamp);
}

beforeEach(function (): void {
    /*
     * Aligned to a minute boundary of the REAL clock — deliberately not a fixed
     * calendar date.
     *
     * Two requirements pull against each other here. TOTP arithmetic needs a
     * deterministic instant, which argues for a hard-coded timestamp. But these
     * tests also drive `AttemptStore::transition()`, and the store evaluates
     * expiry with the database's `CURRENT_TIMESTAMP` rather than the frozen
     * application clock — that app-clock/database-clock seam is documented on
     * `DatabaseAttemptStore::now()`. An attempt whose `expires_at` is computed
     * from a frozen 2026-08-13 12:00 is compared against the database's real
     * clock, so the moment real time passes 12:10 the transition returns
     * `Expired` and three replay tests fail. Permanently, from that day on.
     *
     * That is exactly what happened: the suite was green while it ran before
     * the threshold and began failing after, with nothing in the code changed.
     *
     * Anchoring to real `now()` keeps the two clocks in agreement, and
     * `startOfMinute()` restores the determinism the arithmetic needs: a unix
     * timestamp at :00 seconds is divisible by 60, hence by both the default
     * 30-second period and the 60-second period the non-default-config test
     * uses, so every candidate step lands on an exact boundary either way.
     *
     * Calls Carbon::setTestNow() directly rather than the equivalent
     * $this->travelTo(): PHPStan/Larastan cannot resolve $this inside a Pest
     * closure to Fissible\Vouch\Tests\TestCase (which is where travelTo() —
     * from Illuminate's InteractsWithTime — actually lives), only to the base
     * PHPUnit\Framework\TestCase. Reading travelTo()'s source confirms it does
     * nothing more than this call.
     */
    Carbon::setTestNow(Carbon::now('UTC')->startOfMinute());
});

it('describes itself as a single possession factor', function (): void {
    expect(totpFactor()->id())->toBe('totp')
        ->and(totpFactor()->strength())->toBe(FactorStrength::Possession)
        ->and(totpFactor()->maxActiveCredentials())->toBe(1);
});

it('returns a provisioning uri as a one-time secret, not a plain string', function (): void {
    $result = totpFactor()->enroll(7, ['label' => 'ada@acme.example']);

    expect($result->credentials)->toHaveCount(1)
        ->and($result->secrets)->toHaveCount(1);

    $uri = $result->secrets[0]->reveal();

    expect($uri)->toStartWith('otpauth://totp/')
        ->and($uri)->toContain('issuer=');
});

it('encrypts the seed at rest', function (): void {
    totpFactor()->enroll(7, ['label' => 'ada@acme.example']);

    $raw = \Illuminate\Support\Facades\DB::table('auth_credentials')->where('user_id', 7)->value('secret');
    $model = AuthCredential::where('user_id', 7)->firstOrFail();

    expect($raw)->not->toBe($model->secret);
});

it('accepts the current code and advances the timestep', function (): void {
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    $result = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now)],
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->mutations[0])->toBeInstanceOf(AdvanceCredentialTimestep::class);

    expect(timestepOf($result))->toBe(intdiv($now, TOTP_PERIOD));
});

it('accepts a code from the previous step within the drift window', function (): void {
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    $result = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now - TOTP_PERIOD)],
    ));

    expect($result->isSatisfied())->toBeTrue();
    expect(timestepOf($result))->toBe(intdiv($now, TOTP_PERIOD) - 1);
});

it('reports the timestep it actually matched, not the current one', function (): void {
    /*
     * The whole reason this driver does not use otphp's $leeway parameter.
     * verify() with a leeway returns bool and checks three timestamps
     * internally, so the matched step is unrecoverable — and a replay guard that
     * cannot name the step it consumed permits the replay it appears to prevent.
     */
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    $previous = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now - TOTP_PERIOD)],
    ));

    expect(timestepOf($previous))->not->toBe(intdiv($now, TOTP_PERIOD));
});

it('rejects a code outside the drift window', function (): void {
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now - (5 * TOTP_PERIOD))],
    ))->failure)->toBe(FactorFailure::Mismatch);
});

it('rejects a code two steps past the drift window boundary', function (): void {
    /*
     * The window is configured as 1 (three candidate steps: T-1, T, T+1). A
     * code five steps away, above, only proves the driver isn't unbounded —
     * it does not pin the boundary itself. An off-by-one that widens the loop
     * to T-2..T+2 would still pass every other test in this file; this one
     * exists to catch exactly that regression, on both sides.
     */
    $secret = enrollTotp();
    $now = now()->getTimestamp();

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, $now - (2 * TOTP_PERIOD))],
    ))->failure)->toBe(FactorFailure::Mismatch)
        ->and(totpFactor()->verify(new VerificationRequest(
            attempt: totpAttempt(),
            input: ['code' => codeAt($secret, $now + (2 * TOTP_PERIOD))],
        ))->failure)->toBe(FactorFailure::Mismatch);
});

it('refuses a replay of the same code once the store has recorded it', function (): void {
    // RFC 6238 §5.2: an accepted OTP must not be accepted a second time.
    $secret = enrollTotp();
    $attempt = totpAttempt();
    $code = codeAt($secret, now()->getTimestamp());

    $first = totpFactor()->verify(new VerificationRequest($attempt, ['code' => $code]));
    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        ...$first->mutations,
    ))->toBe(TransitionOutcome::Succeeded);

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => $code],
    ))->failure)->toBe(FactorFailure::Consumed);
});

it('refuses a replay across the leeway window, which a last_used_at guard would allow', function (): void {
    /*
     * The concrete case Amendment B exists for. A code from step T+1 is accepted
     * while the wall clock sits in period T. Deriving the timestep from a
     * last_used_at written at that moment yields T, so replaying the T+1 code
     * passes a `>` check again. Recording the matched STEP closes it.
     */
    $secret = enrollTotp();
    $now = now()->getTimestamp();
    $nextStepCode = codeAt($secret, $now + TOTP_PERIOD);
    $attempt = totpAttempt();

    $first = totpFactor()->verify(new VerificationRequest($attempt, ['code' => $nextStepCode]));
    expect($first->isSatisfied())->toBeTrue();
    expect(timestepOf($first))->toBe(intdiv($now, TOTP_PERIOD) + 1);

    app(AttemptStore::class)->transition($attempt, AttemptState::FactorSatisfied, ...$first->mutations);

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => $nextStepCode],
    ))->failure)->toBe(FactorFailure::Consumed);
});

it('leaves the store as the authoritative replay guard', function (): void {
    /*
     * The driver's own last_used_timestep check is a fast path, not the
     * guarantee: two concurrent submissions can both read the old watermark
     * before either writes. This attacks the store's guarded predicate directly,
     * bypassing the driver, to prove the atomic guard is the real one.
     */
    $secret = enrollTotp();
    $credential = AuthCredential::where('user_id', 7)->firstOrFail();
    $step = intdiv(now()->getTimestamp(), TOTP_PERIOD);
    $attempt = totpAttempt();

    app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, $step),
    );

    expect(app(AttemptStore::class)->transition(
        totpAttempt(),
        AttemptState::FactorSatisfied,
        new AdvanceCredentialTimestep($credential->id, $step),
    ))->toBe(TransitionOutcome::TimestepReplay);
});

it('issues no challenge', function (): void {
    expect(totpFactor()->challenge(new \Fissible\Vouch\Factors\ChallengeRequest(totpAttempt())))->toBeNull();
});

it('reports malformed input rather than a mismatch', function (): void {
    enrollTotp();

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => 12345],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('reports an empty code as malformed, as every driver does', function (): void {
    // Cross-driver invariant: '' is never a code attempt. Pinned in all five
    // driver tests so the answer cannot drift apart again.
    enrollTotp();

    expect(totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => ''],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('honours a non-default period, digits, window and issuer', function (): void {
    /*
     * Every other test in this file resolves TotpFactor through the
     * container-bound singleton, which always reflects config's defaults —
     * and those defaults happen to coincide with otphp's own (period 30,
     * digits 6). Deleting setPeriod()/setDigits() from the driver would
     * leave the whole rest of the suite green. Construct the driver
     * directly with non-default values to close that hole, and check the
     * issuer the same way rather than the earlier test's mere
     * ->toContain('issuer='), which a hardcoded issuer would also satisfy.
     */
    $driver = new TotpFactor(
        app(\Fissible\Vouch\Enrollment\EnrollmentGuard::class),
        app(\Psr\Clock\ClockInterface::class),
        'Acme',
        60,
        8,
        0,
    );

    $enrollment = $driver->enroll(7, ['label' => 'ada@acme.example']);

    expect($enrollment->secrets[0]->reveal())->toContain('issuer=Acme');

    $secret = (string) AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;
    $now = now()->getTimestamp();
    $code = codeAtWith($secret, $now, 60, 8);

    expect(strlen($code))->toBe(8);

    $result = $driver->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => $code],
    ));

    expect($result->isSatisfied())->toBeTrue();
    expect(timestepOf($result))->toBe(intdiv($now, 60));

    // Zero-tolerance window: the default (1) would accept a code one step
    // either side; this configuration must not.
    expect($driver->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAtWith($secret, $now - 60, 60, 8)],
    ))->failure)->toBe(FactorFailure::Mismatch)
        ->and($driver->verify(new VerificationRequest(
            attempt: totpAttempt(),
            input: ['code' => codeAtWith($secret, $now + 60, 60, 8)],
        ))->failure)->toBe(FactorFailure::Mismatch);
});

it('never reports aal3-eligible attributes', function (): void {
    // NIST AAL3 requires a non-exportable private key in hardware. A TOTP seed
    // is neither, and defaulting these false is the fail-closed direction.
    $secret = enrollTotp();

    $result = totpFactor()->verify(new VerificationRequest(
        attempt: totpAttempt(),
        input: ['code' => codeAt($secret, now()->getTimestamp())],
    ));

    expect($result->factor?->isMultiFactor)->toBeFalse()
        ->and($result->factor?->userVerified)->toBeFalse()
        ->and($result->factor?->phishingResistant)->toBeFalse();
});
