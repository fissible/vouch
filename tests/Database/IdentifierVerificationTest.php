<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\VerificationRequest as FactorVerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Verification\IdentifierVerificationOutcome;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);



/*
 * 2.3d Task 1. The ceremony proves control of an identifier and sets
 * verified_at. It is deliberately NOT an authentication and a verification code
 * is deliberately NOT a login factor; the separation is structural, so these
 * tests assert on reachability rather than on a flag.
 *
 * vouch:doctor is part of Task 1's spec but already shipped in c7363cd/00c9f64
 * and is covered by tests/Console/VouchDoctorCommandTest.php. It is deliberately
 * not duplicated here.
 */

function verificationRequest(string $value, string $type = 'email'): IdentifierVerificationRequest
{
    return new IdentifierVerificationRequest(
        type: $type,
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function seedIdentifier(string $value, ?string $verifiedAt, int $userId): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => $verifiedAt,
    ]);
}

/**
 * Request a code and recover it the way production delivers it: through the
 * asynchronous outbox and the bound OtpDelivery. Nothing test-only is exposed
 * by the ceremony itself, and a synchronous or plaintext-retaining send path
 * cannot satisfy this helper.
 */
function requestAndDeliver(string $value): ArrayOtpDelivery
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    app(IdentifierVerifier::class)->request(verificationRequest($value));

    foreach (DB::table('auth_identifier_verification_outbox')->pluck('opaque_id') as $opaqueId) {
        app(VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery;
}

/**
 * A code guaranteed to differ from $code. Asserting with a literal like
 * '000000' is a one-in-a-million flake, and a security test that fails once a
 * year gets quarantined rather than fixed.
 */
function wrongCodeFor(string $code): string
{
    $first = substr($code, 0, 1);

    return ($first === '0' ? '1' : '0') . substr($code, 1);
}

/** Ceremony-dimension throttle consumption, which decoys must also charge. */
function ceremonyCount(): int
{
    return (int) DB::table('auth_throttle_counters')
        ->where('dimension', 'ceremony')
        ->sum('count');
}

it('does not authenticate or create login artifacts', function (): void {
    $identifier = seedIdentifier('ada@acme.example', null, 1);
    $delivery = requestAndDeliver('ada@acme.example');

    $outcome = app(IdentifierVerifier::class)
        ->redeem(verificationRequest('ada@acme.example'), $delivery->lastCode());

    expect($outcome)->toBe(IdentifierVerificationOutcome::Verified)
        ->and($identifier->refresh()->verified_at)->not->toBeNull()
        ->and(AuthSession::query()->count())->toBe(0)
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(DB::table('auth_attempts')->count())->toBe(0)
        ->and(DB::table('auth_token_assurances')->count())->toBe(0);
});

it('delivers to an unverified target that login delivery would refuse', function (): void {
    seedIdentifier('ada@acme.example', null, 1);

    $delivery = requestAndDeliver('ada@acme.example');

    /*
     * OtpChallengeOutbox::issue() throws for verified_at === null and that guard
     * stays. The ceremony needs the opposite rule for this purpose only, so the
     * send must succeed here while creating no login challenge.
     */
    expect($delivery->sent)->toHaveCount(1)
        ->and($delivery->lastIdentifier()->value)->toBe('ada@acme.example')
        ->and(AuthChallenge::query()->count())->toBe(0)
        ->and(DB::table('auth_challenge_outbox')->count())->toBe(0);
});

it('cannot be redeemed as a login factor', function (): void {
    /*
     * The strongest form of the separation: a live ceremony code, submitted to
     * a live login challenge for the same identifier, must fail. A flag-based
     * design would pass every other test in this file and fail this one.
     */
    $identifier = seedIdentifier('ada@acme.example', now()->toDateTimeString(), 7);
    $ceremony = requestAndDeliver('ada@acme.example');
    $ceremonyCode = $ceremony->lastCode();

    $loginDelivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $loginDelivery);
    app()->forgetInstance(EmailOtpFactor::class);
    $factor = app(EmailOtpFactor::class);
    $credential = $factor->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];

    $attempt = AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 7,
        'identifier' => $identifier->value,
        'bound_context' => str_repeat('o', 64),
        'expires_at' => now()->addMinutes(10),
    ]);

    $factor->challenge(new ChallengeRequest($attempt, $credential));
    $loginDelivery->deliverLatestPending();

    /*
     * If the two codes happened to collide, a passing assertion would prove
     * nothing about separation. Skew the ceremony code so it is guaranteed
     * distinct, and submit that.
     */
    $loginCode = $loginDelivery->lastCode();
    $distinct = $ceremonyCode === $loginCode ? wrongCodeFor($ceremonyCode) : $ceremonyCode;

    $refused = $factor->verify(new FactorVerificationRequest($attempt, ['code' => $distinct]));

    /*
     * Positive control. Without it a factor that rejects every code passes this
     * test, and the separation it claims to prove would be indistinguishable
     * from a broken verifier.
     */
    $accepted = $factor->verify(new FactorVerificationRequest($attempt->refresh(), ['code' => $loginCode]));

    expect($refused->isSatisfied())->toBeFalse()
        ->and($accepted->isSatisfied())->toBeTrue();
});

it('consumes a code exactly once', function (): void {
    seedIdentifier('ada@acme.example', null, 1);
    $delivery = requestAndDeliver('ada@acme.example');
    $verifier = app(IdentifierVerifier::class);
    $code = $delivery->lastCode();

    expect($verifier->redeem(verificationRequest('ada@acme.example'), $code))
        ->toBe(IdentifierVerificationOutcome::Verified)
        ->and($verifier->redeem(verificationRequest('ada@acme.example'), $code))
        ->toBe(IdentifierVerificationOutcome::Refused);
});

it('does not consume a live code when a wrong one is submitted', function (): void {
    $identifier = seedIdentifier('ada@acme.example', null, 1);
    $delivery = requestAndDeliver('ada@acme.example');
    $verifier = app(IdentifierVerifier::class);

    expect($verifier->redeem(verificationRequest('ada@acme.example'), wrongCodeFor($delivery->lastCode())))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and($identifier->refresh()->verified_at)->toBeNull()
        ->and($verifier->redeem(verificationRequest('ada@acme.example'), $delivery->lastCode()))
        ->toBe(IdentifierVerificationOutcome::Verified);
});

it('refuses a redemption after its own ttl elapses', function (): void {
    Config::set('vouch.verification.ttl_seconds', 300);
    $identifier = seedIdentifier('ada@acme.example', null, 1);
    $delivery = requestAndDeliver('ada@acme.example');

    /*
     * Provided by Testbench's TestCase via InteractsWithTime. PHPStan types the
     * Pest closure's $this as PHPUnit\Framework\TestCase and cannot see it; the
     * global travel() helper is not equivalent here and fails at runtime.
     *
     * @phpstan-ignore method.notFound
     */
    $this->travel(301)->seconds();

    expect(app(IdentifierVerifier::class)->redeem(verificationRequest('ada@acme.example'), $delivery->lastCode()))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and($identifier->refresh()->verified_at)->toBeNull();
});

it('charges the ceremony dimension equally for every identifier state', function (): void {
    seedIdentifier('unverified@acme.example', null, 1);
    seedIdentifier('verified@acme.example', now()->toDateTimeString(), 2);

    $observed = [];

    foreach (['nobody@acme.example', 'unverified@acme.example', 'verified@acme.example'] as $value) {
        $before = [
            'ceremony' => ceremonyCount(),
            'records' => DB::table('auth_identifier_verifications')->count(),
            'outbox' => DB::table('auth_identifier_verification_outbox')->count(),
        ];

        /*
         * request() returns void deliberately -- there is nothing for it to
         * leak -- so neutrality is measured in effects. Comparing its result
         * would compare nulls and pass against any implementation.
         */
        app(IdentifierVerifier::class)->request(verificationRequest($value));

        $observed[$value] = [
            'ceremony' => ceremonyCount() - $before['ceremony'],
            'records' => DB::table('auth_identifier_verifications')->count() - $before['records'],
            'outbox' => DB::table('auth_identifier_verification_outbox')->count() - $before['outbox'],
        ];
    }

    $shapes = array_values($observed);

    /*
     * A decoy that is not charged is an oracle: an attacker who can exhaust the
     * ceremony budget only for real addresses learns which ones are real.
     */
    expect($shapes[0])->toEqual($shapes[1])
        ->and($shapes[1])->toEqual($shapes[2])
        ->and($shapes[0]['ceremony'])->toBeGreaterThan(0)
        ->and(ceremonyCount())->toBeGreaterThan(0)
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'identifier')->sum('count'))
        ->toBe(0);
});

it('never redeems one identifier\'s code against another', function (): void {
    $ada = seedIdentifier('ada@acme.example', null, 1);
    $bob = seedIdentifier('bob@acme.example', null, 2);

    $adaCode = requestAndDeliver('ada@acme.example')->lastCode();
    requestAndDeliver('bob@acme.example');

    /*
     * A lookup keyed on the code alone rather than on (identifier, code) would
     * verify the wrong account here. Refusing unknown submitted identifiers is
     * not sufficient protection: both of these exist.
     */
    $verifier = app(IdentifierVerifier::class);

    expect($verifier->redeem(verificationRequest('bob@acme.example'), $adaCode))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and($ada->refresh()->verified_at)->toBeNull()
        ->and($bob->refresh()->verified_at)->toBeNull()
        /*
         * The misdirected attempt must not burn Ada's code either. Refusing by
         * consuming would let anyone disable a pending verification for an
         * address they do not control.
         */
        ->and($verifier->redeem(verificationRequest('ada@acme.example'), $adaCode))
        ->toBe(IdentifierVerificationOutcome::Verified)
        ->and($ada->refresh()->verified_at)->not->toBeNull();
});

it('never verifies a real identifier through a decoy ceremony', function (): void {
    $identifier = seedIdentifier('ada@acme.example', null, 1);
    $liveCode = requestAndDeliver('ada@acme.example')->lastCode();

    $decoy = requestAndDeliver('nobody@acme.example');

    expect($decoy->sent)->toBe([])
        ->and(app(IdentifierVerifier::class)->redeem(verificationRequest('nobody@acme.example'), $liveCode))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and($identifier->refresh()->verified_at)->toBeNull()
        ->and(AuthIdentifier::query()->whereNotNull('verified_at')->count())->toBe(0);
});

it('treats re-verification exactly like first verification', function (): void {
    $identifier = seedIdentifier('ada@acme.example', now()->subDay()->toDateTimeString(), 1);
    $first = $identifier->verified_at;

    $before = ceremonyCount();
    $delivery = requestAndDeliver('ada@acme.example');
    $charged = ceremonyCount() - $before;

    $outcome = app(IdentifierVerifier::class)
        ->redeem(verificationRequest('ada@acme.example'), $delivery->lastCode());

    expect($outcome)->toBe(IdentifierVerificationOutcome::Verified)
        ->and($delivery->sent)->toHaveCount(1)
        ->and($charged)->toBeGreaterThan(0)
        ->and($first)->not->toBeNull()
        ->and($identifier->refresh()->verified_at?->greaterThan($first ?? now()))->toBeTrue()
        ->and(AuthSession::query()->count())->toBe(0);
});

it('refuses a wrong code identically for known and unknown identifiers', function (): void {
    seedIdentifier('ada@acme.example', null, 1);
    $verifier = app(IdentifierVerifier::class);

    $delivery = requestAndDeliver('ada@acme.example');
    $wrong = wrongCodeFor($delivery->lastCode());
    $verifier->request(verificationRequest('nobody@acme.example'));

    expect($verifier->redeem(verificationRequest('ada@acme.example'), $wrong))
        ->toBe(IdentifierVerificationOutcome::Refused)
        ->and($verifier->redeem(verificationRequest('nobody@acme.example'), $wrong))
        ->toBe(IdentifierVerificationOutcome::Refused);
});
