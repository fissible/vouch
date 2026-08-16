<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Notifications\OtpChallengeOutbox;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

/*
 * The last of Factors group 1: OtpFactor's defaults, its two reachable
 * instanceof guards, the exactly-at-expiry boundary, and its assurance
 * attributes.
 */

/** A clock the test drives, so expiry can be tested AT the boundary rather than near it. */
final class SteppableClock implements ClockInterface
{
    public function __construct(private DateTimeImmutable $now) {}

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now = $this->now->modify('+' . $seconds . ' seconds');
    }
}

function otpAttemptFor(int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'user_id' => $userId,
        'bound_context' => str_repeat('e', 64),
        'expires_at' => now()->addMinutes(10),
    ]);
}

function otpIdentifierFor(int $userId = 7): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);
}

it('rejects an enrollment against an identifier that does not exist', function (): void {
    /*
     * `find()` returns null for a missing row, and the guard is what turns that
     * into a refusal. Without it the driver enrols a credential pointing at a
     * row that is not there -- a credential nothing can ever deliver to.
     */
    $delivery = new ArrayOtpDelivery();
    $factor = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        app(ClockInterface::class),
        app(OtpChallengeOutbox::class),
        app(AuthThrottleStore::class),
    );

    expect(fn () => $factor->enroll(7, ['identifier_id' => 999_999]))
        ->toThrow(InvalidArgumentException::class, 'Identifier 999999 does not exist.');
});

it('reports no credential when there is no challenge to verify against', function (): void {
    /*
     * A submitted code with no outstanding challenge. Without the guard the
     * driver dereferences null on a public code path -- a 500 where a refusal
     * belongs, and one an attacker can trigger at will.
     */
    $factor = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        app(ClockInterface::class),
        app(OtpChallengeOutbox::class),
        app(AuthThrottleStore::class),
    );

    $result = $factor->verify(new VerificationRequest(otpAttemptFor(), ['code' => '123456']));

    expect($result->failure)->toBe(FactorFailure::NoCredential);
});

it('issues codes of its documented default length and lifetime', function (): void {
    /*
     * Built with NO length or ttl argument, so the constructor's own defaults
     * are what gets read. Passing them explicitly would prove nothing -- the
     * lesson the TOTP defaults test had to learn twice.
     */
    $clock = new SteppableClock(new DateTimeImmutable('2026-08-13T12:00:00+00:00'));
    $delivery = new ArrayOtpDelivery();
    $factor = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        $clock,
        app(OtpChallengeOutbox::class),
        app(AuthThrottleStore::class),
    );

    $factor->enroll(7, ['identifier_id' => otpIdentifierFor()->id]);
    /*
     * Issuance writes a database-clock deadline, so bound it with two expected
     * 120-second deadlines from that same authority. A PHP-clock upper bound
     * sampled before the insert was one second behind PostgreSQL at a real
     * matrix boundary; adding 120 to DatabaseTime::current() still missed that
     * PostgreSQL rounds CURRENT_TIMESTAMP(0), so the expected deadline must use
     * the same portable interval expression as the production deadline.
     */
    $before = app(DatabaseTime::class)->deadline(120)->getTimestamp();
    $challenge = $factor->challenge(new ChallengeRequest(otpAttemptFor()));
    $after = app(DatabaseTime::class)->deadline(120)->getTimestamp();
    $expiry = $challenge?->expires_at->getTimestamp();
    $delivery->deliverLatestPending();

    expect(strlen($delivery->lastCode()))->toBe(6)
        ->and($expiry)->toBeGreaterThanOrEqual($before)
        ->and($expiry)->toBeLessThanOrEqual($after);
});

it('treats a code as expired at its expiry instant, not one second after', function (): void {
    /*
     * `expires_at <= now` read as `<` accepts a code at the exact instant it
     * expires. One second of an OTP's life is not a security incident on its
     * own, but the boundary is the whole meaning of a lifetime, and nothing
     * else in the suite tests AT it -- every other expiry test is comfortably
     * past.
     */
    $delivery = new ArrayOtpDelivery();
    $issuer = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        app(ClockInterface::class),
        app(OtpChallengeOutbox::class),
        app(AuthThrottleStore::class),
        6,
        120,
    );

    $issuer->enroll(7, ['identifier_id' => otpIdentifierFor()->id]);
    $attempt = otpAttemptFor();
    $challenge = $issuer->challenge(new ChallengeRequest($attempt));
    $delivery->deliverLatestPending();
    $code = $delivery->lastCode();

    if ($challenge === null) {
        throw new RuntimeException('Expected the OTP challenge to be issued.');
    }

    $clock = new SteppableClock($challenge->expires_at->toDateTimeImmutable()->modify('-1 second'));
    $verifier = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        $clock,
        app(OtpChallengeOutbox::class),
        app(AuthThrottleStore::class),
        6,
        120,
    );

    // One second before the deadline: still good.
    $early = $verifier->verify(new VerificationRequest($attempt, ['code' => $code]));

    // Exactly at the deadline: expired.
    $clock->advance(1);
    $atDeadline = $verifier->verify(new VerificationRequest($attempt, ['code' => $code]));

    expect($early->failure)->toBeNull()
        ->and($atDeadline->failure)->toBe(FactorFailure::Expired);
});

it('never reports aal3-eligible attributes for an emailed code', function (): void {
    /*
     * Hard-coded false because a code emailed to an inbox is not multi-factor,
     * not user-verifying and not phishing-resistant.
     *
     * Not a live exposure today -- the default assurance vocabulary caps at AAL2
     * -- but an unasserted `false` becomes load-bearing the moment an AAL3 rung
     * is added, and nothing outside TOTP and recovery codes was asserting these.
     */
    $clock = new SteppableClock(new DateTimeImmutable('2026-08-13T12:00:00+00:00'));
    $delivery = new ArrayOtpDelivery();
    $factor = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        $clock,
        app(OtpChallengeOutbox::class),
        app(AuthThrottleStore::class),
    );

    $factor->enroll(7, ['identifier_id' => otpIdentifierFor()->id]);
    $attempt = otpAttemptFor();
    $factor->challenge(new ChallengeRequest($attempt));
    $delivery->deliverLatestPending();

    $result = $factor->verify(new VerificationRequest($attempt, ['code' => $delivery->lastCode()]));
    $satisfied = $result->factor;

    expect($result->failure)->toBeNull()
        ->and($satisfied)->not->toBeNull()
        ->and($satisfied?->isMultiFactor)->toBeFalse()
        ->and($satisfied?->userVerified)->toBeFalse()
        ->and($satisfied?->phishingResistant)->toBeFalse();
});
