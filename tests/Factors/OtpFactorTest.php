<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;

uses(RefreshDatabase::class);

/**
 * Stands in for `$this->delivery`. PHPStan cannot resolve $this inside a Pest
 * closure any further than the base PHPUnit\Framework\TestCase (see the same
 * note in TotpFactorTest, about $this->travelTo()), so a dynamic
 * $this->delivery property is unanalysable. A function-scoped static plays the
 * same role — bound fresh in beforeEach(), read by every test — without it.
 */
function otpDelivery(?ArrayOtpDelivery $bind = null): ArrayOtpDelivery
{
    static $delivery = null;

    if ($bind instanceof ArrayOtpDelivery) {
        $delivery = $bind;
    }

    if (! $delivery instanceof ArrayOtpDelivery) {
        throw new RuntimeException('otpDelivery() was read before beforeEach() bound it.');
    }

    return $delivery;
}

function deliveredOtpCode(): string
{
    otpDelivery()->deliverLatestPending();

    return otpDelivery()->lastCode();
}

function deliveredOtpIdentifier(): AuthIdentifier
{
    otpDelivery()->deliverLatestPending();

    return otpDelivery()->lastIdentifier();
}

/**
 * Narrows AuthChallenge|null to AuthChallenge for PHPStan via a real check,
 * mirroring the isSatisfied()/timestepOf() narrowing pattern used in
 * RecoveryCodeFactorTest and TotpFactorTest. challenge() is legitimately
 * nullable for factors that issue none — password, TOTP, recovery code — but
 * every OTP test that reaches here already knows a challenge was issued.
 */
function requireChallenge(?AuthChallenge $challenge): AuthChallenge
{
    if (! $challenge instanceof AuthChallenge) {
        throw new RuntimeException('Expected an OTP challenge to have been issued.');
    }

    return $challenge;
}

beforeEach(function (): void {
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    otpDelivery($delivery);
});

function emailOtp(): EmailOtpFactor
{
    return app(EmailOtpFactor::class);
}

function otpAttempt(?int $userId = 7): AuthAttempt
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

function verifiedEmail(int $userId = 7, string $value = 'ada@acme.example'): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

it('describes itself as a weak possession factor with no cardinality limit', function (): void {
    expect(emailOtp()->id())->toBe('email_otp')
        ->and(emailOtp()->strength())->toBe(FactorStrength::PossessionWeak)
        ->and(emailOtp()->maxActiveCredentials())->toBeNull();
});

it('enrolls a secretless credential bound to a verified identifier', function (): void {
    $identifier = verifiedEmail();

    $result = emailOtp()->enroll(7, ['identifier_id' => $identifier->id]);

    expect($result->credentials)->toHaveCount(1)
        ->and($result->secrets)->toBe([])
        ->and($result->credentials[0]->identifier_id)->toBe($identifier->id)
        ->and($result->credentials[0]->secret)->toBeNull();
});

it('re-enables rather than duplicating on re-enrollment, preserving the credential id', function (): void {
    /*
     * The unique (user_id, type, identifier_id) index counts disabled rows, and
     * a partial index is not portable across the three engines. Preserving the
     * ID keeps auth_token_assurances.credential_ids references and kernel
     * distinctness coherent — a new row would silently orphan both.
     *
     * Honest only because OTP credentials are secretless: the code lives in
     * auth_challenges, so re-enrollment genuinely IS re-enabling. Password and
     * TOTP must still create a fresh row with a new secret.
     */
    $identifier = verifiedEmail();
    $first = emailOtp()->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];
    emailOtp()->revoke($first);

    $second = emailOtp()->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];

    expect($second->id)->toBe($first->id)
        ->and($second->disabled_at)->toBeNull()
        ->and(AuthCredential::where('user_id', 7)->count())->toBe(1);
});

it('refuses to enroll against an unverified identifier', function (): void {
    $identifier = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'unproven@acme.example', 'verified_at' => null,
    ]);

    emailOtp()->enroll(7, ['identifier_id' => $identifier->id]);
})->throws(\Fissible\Vouch\Persistence\IdentifierLinkageViolation::class);

it('refuses to enroll against an identifier of the wrong type', function (): void {
    // A phone number is not an email address. Without this the SMS and email
    // drivers would each happily deliver to the other's identifiers.
    $phone = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'phone', 'value' => '+15550100', 'verified_at' => now(),
    ]);

    emailOtp()->enroll(7, ['identifier_id' => $phone->id]);
})->throws(InvalidArgumentException::class);

it('delivers a code and records the challenge against the credential', function (): void {
    $identifier = verifiedEmail();
    $credential = emailOtp()->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];
    $attempt = otpAttempt();

    $challenge = requireChallenge(emailOtp()->challenge(new ChallengeRequest(
        attempt: $attempt,
        credential: $credential,
        clientIp: '198.51.100.7',
        clientUserAgent: 'Mozilla/5.0',
    )));

    expect($challenge)->toBeInstanceOf(AuthChallenge::class)
        ->and($challenge->credential_id)->toBe($credential->id)
        ->and($challenge->bound_ip)->toBe('198.51.100.7')
        ->and($challenge->bound_user_agent)->toBe('Mozilla/5.0')
        ->and(deliveredOtpIdentifier()->id)->toBe($identifier->id);
});

it('never stores the delivered code in plaintext', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];

    $challenge = requireChallenge(emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $credential)));

    expect($challenge->code_hash)->not->toBe(deliveredOtpCode())
        ->and($challenge->getAttributes())->not->toHaveKey('code');
});

it('generates a code of the configured length, all digits', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $credential));

    expect(deliveredOtpCode())->toHaveLength(6)
        ->and(otpDelivery()->lastCode())->toMatch('/^\d{6}$/');
});

it('satisfies with the delivered code and returns a consume mutation', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential, '198.51.100.7', 'UA'));

    $result = emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => deliveredOtpCode()],
        challenge: $challenge,
        clientIp: '198.51.100.7',
        clientUserAgent: 'UA',
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->mutations[0])->toBeInstanceOf(ConsumeChallenge::class);
});

it('reports the credential the code was actually delivered against', function (): void {
    /*
     * The reason Amendment D exists. With OTP on two verified addresses, a code
     * delivered to one must not be attributed to the other — require_distinct_
     * credentials keys on this value, and would otherwise pass while describing
     * a delivery that never happened.
     */
    $first = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada@acme.example')->id])->credentials[0];
    $second = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada+alt@acme.example')->id])->credentials[0];

    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $second));

    $result = emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => deliveredOtpCode()],
        challenge: $challenge,
    ));

    expect($result->factor?->credentialId)->toBe((string) $second->id)
        ->and($result->factor?->credentialId)->not->toBe((string) $first->id);
});

it('refuses a code submitted from a different ip', function (): void {
    // bound_ip written and never read would be the vacuous-control shape this
    // project keeps finding. This is the test that makes it load-bearing.
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential, '198.51.100.7', 'UA'));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => deliveredOtpCode()],
        challenge: $challenge,
        clientIp: '203.0.113.9',
        clientUserAgent: 'UA',
    ))->failure)->toBe(FactorFailure::BindingMismatch);
});

it('refuses a code submitted from a different user agent', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential, '198.51.100.7', 'UA'));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => deliveredOtpCode()],
        challenge: $challenge,
        clientIp: '198.51.100.7',
        clientUserAgent: 'SomethingElse',
    ))->failure)->toBe(FactorFailure::BindingMismatch);
});

it('refuses a wrong code without consuming the challenge', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = requireChallenge(emailOtp()->challenge(new ChallengeRequest($attempt, $credential)));

    $result = emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => '000000'],
        challenge: $challenge,
    ));

    expect($result->failure)->toBe(FactorFailure::Mismatch)
        ->and($result->mutations)->toBe([])
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->toBeNull();
});

it('refuses an expired challenge', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential));
    $code = deliveredOtpCode();

    Carbon::setTestNow(now()->addMinutes(5));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::Expired);
});

it('refuses a challenge at its exact expiry boundary', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = requireChallenge(emailOtp()->challenge(new ChallengeRequest($attempt, $credential)));
    $code = deliveredOtpCode();

    Carbon::setTestNow($challenge->expires_at);

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::Expired);
});

it('refuses a challenge already consumed by the store', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = requireChallenge(emailOtp()->challenge(new ChallengeRequest($attempt, $credential)));
    $code = deliveredOtpCode();

    $first = emailOtp()->verify(new VerificationRequest($attempt, ['code' => $code], challenge: $challenge));
    expect(app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        ...$first->mutations,
    ))->toBe(TransitionOutcome::Succeeded);

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: AuthChallenge::findOrFail($challenge->id),
    ))->failure)->toBe(FactorFailure::Consumed);
});

it('refuses a challenge belonging to a different attempt', function (): void {
    // Otherwise a challenge id observed elsewhere could be redeemed here.
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $challenge = emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $credential));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: otpAttempt(),
        input: ['code' => deliveredOtpCode()],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::BindingMismatch);
});

it('refuses to challenge when the user has several otp credentials and none was named', function (): void {
    // Choosing one silently would deliver to an address the user did not pick.
    emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada@acme.example')->id]);
    emailOtp()->enroll(7, ['identifier_id' => verifiedEmail(7, 'ada+alt@acme.example')->id]);

    emailOtp()->challenge(new ChallengeRequest(otpAttempt()));
})->throws(InvalidArgumentException::class);

it('resolves the only otp credential when none was named', function (): void {
    emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id]);

    expect(emailOtp()->challenge(new ChallengeRequest(otpAttempt())))->toBeInstanceOf(AuthChallenge::class);
});

it('reports missing input as malformed rather than a mismatch', function (): void {
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => ['array', 'not', 'string']],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('reports an empty code as malformed, as every driver does', function (): void {
    /*
     * Hash::check('', $hashOfEmptyString) is TRUE. With VOUCH_OTP_LENGTH= set but
     * blank the config's `(int) env(...)` yields 0, generateCode() returns '', and
     * an empty submission would satisfy the challenge — and unlike recovery code,
     * OTP is PossessionWeak and DOES count towards satisfiability, so that is a
     * live policy bypass. The constructor now refuses length 0; this is the
     * second lock, on the submission side.
     */
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential));

    expect(emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => ''],
        challenge: $challenge,
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('refuses a live code once the credential it was delivered against is revoked', function (): void {
    /*
     * GuardsChallengeTarget hooks `creating` only, so its disabled_at check fires
     * at delivery and never again. Without a verify-time check, revoking a
     * credential would not take effect until the challenge's TTL ran out, and the
     * driver would return a SatisfiedFactor naming a revoked credential — a
     * security action silently not taking effect. Password, TOTP and recovery
     * code all filter disabled_at at verify time; this is OTP doing the same.
     */
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    $attempt = otpAttempt();
    $challenge = emailOtp()->challenge(new ChallengeRequest($attempt, $credential));
    $code = deliveredOtpCode();

    emailOtp()->revoke($credential);

    $result = emailOtp()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: $challenge,
    ));

    expect($result->isSatisfied())->toBeFalse()
        ->and($result->failure)->toBe(FactorFailure::NoCredential)
        ->and($result->mutations)->toBe([]);
});

it('refuses to challenge a credential belonging to a different factor type', function (): void {
    /*
     * resolveSoleCredential() filters on type; a caller-supplied credential has
     * not been through that filter, and GuardsChallengeTarget checks existence,
     * active, same-user and identifier linkage but never type-vs-factor_type.
     * Without this guard the email driver would deliver to the phone identifier,
     * write factor_type='email_otp', and verify() would satisfy email_otp — so a
     * policy that specifically requires email becomes satisfiable by SMS.
     */
    $phone = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'phone', 'value' => '+15550100', 'verified_at' => now(),
    ]);
    $smsCredential = app(SmsOtpFactor::class)->enroll(7, ['identifier_id' => $phone->id])->credentials[0];

    emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $smsCredential));
})->throws(InvalidArgumentException::class);

it('refuses a revoked credential in the driver, not only in the model guard', function (): void {
    /*
     * GuardsChallengeTarget also rejects a disabled credential, and
     * ChallengeTargetViolation EXTENDS InvalidArgumentException — so a plain
     * ->throws(InvalidArgumentException::class) here would pass with the driver's
     * own guard deleted, and prove nothing. Distinguishing the two exception
     * classes is what makes this test discriminate: the driver must refuse before
     * a code is generated and before any row is offered to the model layer.
     */
    $credential = emailOtp()->enroll(7, ['identifier_id' => verifiedEmail()->id])->credentials[0];
    emailOtp()->revoke($credential);

    try {
        emailOtp()->challenge(new ChallengeRequest(otpAttempt(), $credential));
    } catch (\Fissible\Vouch\Persistence\ChallengeTargetViolation $violation) {
        throw new RuntimeException(
            'The model guard refused this, not the driver: ' . $violation->getMessage(),
        );
    } catch (InvalidArgumentException $refused) {
        expect($refused->getMessage())->toContain('disabled')
            ->and(AuthChallenge::count())->toBe(0);

        return;
    }

    throw new RuntimeException('Expected the driver to refuse a revoked credential.');
});

it('keeps the sms driver on its own type key and identifier type', function (): void {
    $sms = app(SmsOtpFactor::class);
    $phone = AuthIdentifier::create([
        'user_id' => 7, 'type' => 'phone', 'value' => '+15550100', 'verified_at' => now(),
    ]);

    $credential = $sms->enroll(7, ['identifier_id' => $phone->id])->credentials[0];

    expect($sms->id())->toBe('sms_otp')
        ->and($credential->type)->toBe('sms_otp');
});
