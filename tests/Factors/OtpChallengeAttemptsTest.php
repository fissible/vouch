<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function cappedOtpAttempt(): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 7,
        'bound_context' => str_repeat('a', 64),
        'expires_at' => now()->addMinutes(10),
    ]);
}

/** @return array{EmailOtpFactor, AuthAttempt, AuthChallenge, string} */
function issuedCappedOtp(): array
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->forgetInstance(EmailOtpFactor::class);
    $factor = app(EmailOtpFactor::class);
    $identifier = AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'attempt-cap@acme.example',
        'verified_at' => now(),
    ]);
    $credential = $factor->enroll(7, ['identifier_id' => $identifier->id])->credentials[0];
    $attempt = cappedOtpAttempt();
    $challenge = $factor->challenge(new ChallengeRequest($attempt, $credential));

    if (! $challenge instanceof AuthChallenge) {
        throw new RuntimeException('The OTP factor did not issue a challenge.');
    }

    $delivery->deliverLatestPending();

    return [$factor, $attempt, $challenge, $delivery->lastCode()];
}

function wrongOtpFor(string $code): string
{
    return $code === '000000' ? '111111' : '000000';
}

it('allows a correct fifth guess and prevents a sixth request after consumption', function (): void {
    [$factor, $attempt, $challenge, $code] = issuedCappedOtp();
    $wrong = wrongOtpFor($code);

    for ($failure = 1; $failure <= 4; $failure++) {
        expect($factor->verify(new VerificationRequest(
            $attempt,
            ['code' => $wrong],
            challenge: $challenge,
        ))->failure)->toBe(FactorFailure::Mismatch);
    }

    expect(AuthChallenge::findOrFail($challenge->id)->attempts)->toBe(4);

    $fifth = $factor->verify(new VerificationRequest(
        $attempt,
        ['code' => $code],
        challenge: $challenge,
    ));

    expect($fifth->isSatisfied())->toBeTrue()
        ->and(app(AttemptStore::class)->transition(
            $attempt,
            AttemptState::FactorSatisfied,
            ...$fifth->mutations,
        ))->toBe(TransitionOutcome::Succeeded)
        ->and($factor->verify(new VerificationRequest(
            $attempt,
            ['code' => $code],
            challenge: $challenge,
        ))->failure)->toBe(FactorFailure::Consumed);
});

it('invalidates on the fifth wrong guess and never records a sixth', function (): void {
    [$factor, $attempt, $challenge, $code] = issuedCappedOtp();
    $wrong = wrongOtpFor($code);

    for ($failure = 1; $failure <= 5; $failure++) {
        expect($factor->verify(new VerificationRequest(
            $attempt,
            ['code' => $wrong],
            challenge: $challenge,
        ))->failure)->toBe(FactorFailure::Mismatch);
    }

    $invalidated = AuthChallenge::findOrFail($challenge->id);

    expect($invalidated->attempts)->toBe(5)
        ->and($invalidated->consumed_at)->not->toBeNull()
        // Deliberately pass the stale pre-invalidation model. The database
        // writer, not an object snapshot, must still refuse and classify it.
        ->and($factor->verify(new VerificationRequest(
            $attempt,
            ['code' => $wrong],
            challenge: $challenge,
        ))->failure)->toBe(FactorFailure::Consumed)
        ->and(AuthChallenge::findOrFail($challenge->id)->attempts)->toBe(5)
        ->and(DB::table('auth_throttle_locks')->count())->toBe(0);
});

it('does not charge malformed expired consumed or binding-mismatched submissions', function (): void {
    [$factor, $attempt, $challenge, $code] = issuedCappedOtp();
    $wrong = wrongOtpFor($code);

    DB::table('auth_challenges')->where('id', $challenge->id)->update([
        'bound_ip' => '198.51.100.7',
    ]);
    $bound = AuthChallenge::findOrFail($challenge->id);

    expect($factor->verify(new VerificationRequest(
        $attempt,
        ['code' => ''],
        challenge: $bound,
    ))->failure)->toBe(FactorFailure::Malformed)
        ->and($factor->verify(new VerificationRequest(
            $attempt,
            ['code' => $wrong],
            challenge: $bound,
            clientIp: '203.0.113.9',
        ))->failure)->toBe(FactorFailure::BindingMismatch)
        ->and(AuthChallenge::findOrFail($challenge->id)->attempts)->toBe(0);

    DB::table('auth_challenges')->where('id', $challenge->id)->update([
        'expires_at' => now()->subSecond(),
    ]);
    $expired = AuthChallenge::findOrFail($challenge->id);

    expect($factor->verify(new VerificationRequest(
        $attempt,
        ['code' => $wrong],
        challenge: $expired,
        clientIp: '198.51.100.7',
    ))->failure)->toBe(FactorFailure::Expired)
        ->and(AuthChallenge::findOrFail($challenge->id)->attempts)->toBe(0);

    DB::table('auth_challenges')->where('id', $challenge->id)->update([
        'expires_at' => now()->addMinute(),
        'consumed_at' => now(),
    ]);
    $consumed = AuthChallenge::findOrFail($challenge->id);

    expect($factor->verify(new VerificationRequest(
        $attempt,
        ['code' => $wrong],
        challenge: $consumed,
        clientIp: '198.51.100.7',
    ))->failure)->toBe(FactorFailure::Consumed)
        ->and(AuthChallenge::findOrFail($challenge->id)->attempts)->toBe(0);
});

it('does not reset an earlier challenge count when a replacement is issued', function (): void {
    [$factor, $attempt, $first, $code] = issuedCappedOtp();
    $wrong = wrongOtpFor($code);

    $factor->verify(new VerificationRequest($attempt, ['code' => $wrong], challenge: $first));
    $factor->verify(new VerificationRequest($attempt, ['code' => $wrong], challenge: $first));

    $second = $factor->challenge(new ChallengeRequest($attempt));

    if (! $second instanceof AuthChallenge) {
        throw new RuntimeException('The replacement OTP challenge was not issued.');
    }

    expect($second->id)->not->toBe($first->id)
        ->and(AuthChallenge::findOrFail($first->id)->attempts)->toBe(2)
        ->and(AuthChallenge::findOrFail($second->id)->attempts)->toBe(0);
});
