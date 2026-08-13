<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\ChallengeTargetViolation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function targetAttempt(?int $userId = 7): AuthAttempt
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

function targetCredential(int $userId = 7, string $value = 'ada@acme.example'): AuthCredential
{
    $identifier = AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);

    return AuthCredential::create([
        'user_id' => $userId,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ]);
}

/**
 * @param array<string, mixed> $overrides
 */
function makeChallenge(array $overrides = []): AuthChallenge
{
    return AuthChallenge::create(array_merge([
        'attempt_id' => targetAttempt()->id,
        'factor_type' => 'email_otp',
        'code_hash' => 'digest',
        'expires_at' => now()->addMinutes(2),
    ], $overrides));
}

it('records the credential an otp challenge was delivered against', function (): void {
    $attempt = targetAttempt();
    $credential = targetCredential();

    $challenge = makeChallenge(['attempt_id' => $attempt->id, 'credential_id' => $credential->id]);

    expect(AuthChallenge::findOrFail($challenge->id)->credential_id)->toBe($credential->id);
});

it('refuses an otp challenge with no credential target', function (): void {
    /*
     * Without this, verify() would pick a credential after the fact from
     * whatever the user currently has. A user with OTP on two addresses could
     * have a code delivered to one and attributed to the other, and
     * require_distinct_credentials would then pass while describing something
     * that never happened.
     */
    makeChallenge(['credential_id' => null]);
})->throws(ChallengeTargetViolation::class);

it('permits a password challenge with no credential target', function (): void {
    // Password and TOTP issue no challenge and have no delivery target. A
    // NOT NULL column would be a lie; this is where the distinction lives.
    $challenge = makeChallenge(['factor_type' => 'password', 'credential_id' => null]);

    expect($challenge->credential_id)->toBeNull();
});

it('refuses a challenge naming a disabled credential', function (): void {
    $credential = targetCredential();
    $credential->update(['disabled_at' => now()]);

    makeChallenge(['credential_id' => $credential->id]);
})->throws(ChallengeTargetViolation::class);

it('refuses a challenge naming another user credential', function (): void {
    $attempt = targetAttempt(userId: 7);
    $credential = targetCredential(userId: 8, value: 'grace@acme.example');

    makeChallenge(['attempt_id' => $attempt->id, 'credential_id' => $credential->id]);
})->throws(ChallengeTargetViolation::class);

it('refuses a challenge naming a credential with no identifier', function (): void {
    // An OTP credential with no identifier has nowhere to deliver to. Accepting
    // it would mean a challenge whose target cannot be resolved.
    $credential = AuthCredential::create([
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => null,
        'strength' => 'possession_weak',
    ]);

    makeChallenge(['credential_id' => $credential->id]);
})->throws(ChallengeTargetViolation::class);

it('refuses a challenge on an attempt with no identified user', function (): void {
    // Anonymous attempts cannot own a credential-bound challenge; permitting one
    // would skip the same-user check entirely.
    $attempt = targetAttempt(userId: null);

    makeChallenge(['attempt_id' => $attempt->id, 'credential_id' => targetCredential()->id]);
})->throws(ChallengeTargetViolation::class);
