<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentRefused;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function passwordFactor(): PasswordFactor
{
    return app(PasswordFactor::class);
}

function driverAttempt(?int $userId = 7): AuthAttempt
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

it('describes itself as a single knowledge factor', function (): void {
    $factor = passwordFactor();

    expect($factor->id())->toBe('password')
        ->and($factor->kind())->toBe(FactorKind::Knowledge)
        ->and($factor->strength())->toBe(FactorStrength::Knowledge)
        ->and($factor->maxActiveCredentials())->toBe(1);
});

it('stores a digest and never the password', function (): void {
    $result = passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    $credential = $result->credentials[0];

    expect($result->credentials)->toHaveCount(1)
        ->and($result->secrets)->toBe([])
        ->and($credential->secret)->not->toBe('correct horse battery staple')
        ->and(password_get_info((string) $credential->secret)['algo'])->not->toBeNull();
});

it('issues no challenge', function (): void {
    expect(passwordFactor()->challenge(new ChallengeRequest(driverAttempt())))->toBeNull();
});

it('satisfies with the correct password and writes no single-use state', function (): void {
    // Password is not single-use. A driver returning a mutation here would be
    // writing on the verification path for no reason.
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    $result = passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'correct horse battery staple'],
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toBe([])
        ->and($result->factor?->strength)->toBe(FactorStrength::Knowledge)
        ->and($result->factor?->isMultiFactor)->toBeFalse()
        ->and($result->factor?->userVerified)->toBeFalse()
        ->and($result->factor?->phishingResistant)->toBeFalse();
});

it('reports a mismatch truthfully rather than pre-redacting it', function (): void {
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'wrong'],
    ))->failure)->toBe(FactorFailure::Mismatch);
});

it('distinguishes no credential from a wrong password', function (): void {
    // ErrorShaper collapses these under a strict posture. The driver must not,
    // or the strict-posture guarantee becomes unverifiable.
    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'anything'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});

it('equalizes a missing user identity as no credential', function (): void {
    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(null),
        input: ['password' => 'anything'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});

it('reports malformed input rather than treating it as a wrong password', function (): void {
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => ['array', 'not', 'string']],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('refuses to verify against a disabled credential', function (): void {
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);
    AuthCredential::where('user_id', 7)->update(['disabled_at' => now()]);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => 'correct horse battery staple'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});

it('refuses a second password rather than leaving two live', function (): void {
    passwordFactor()->enroll(7, ['password' => 'first']);
    passwordFactor()->enroll(7, ['password' => 'second']);
})->throws(EnrollmentRefused::class);

it('replaces a password in one operation', function (): void {
    passwordFactor()->enroll(7, ['password' => 'first']);
    passwordFactor()->enroll(7, ['password' => 'second', 'replace' => true]);

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(1)
        ->and(passwordFactor()->verify(new VerificationRequest(
            attempt: driverAttempt(),
            input: ['password' => 'second'],
        ))->isSatisfied())->toBeTrue();
});

it('reports malformed rather than comparing an empty password', function (): void {
    /*
     * password_verify('', password_hash('', PASSWORD_BCRYPT)) returns TRUE. Any
     * path that lets '' reach Hash::check() is one stored empty hash away from a
     * universal bypass, so the driver refuses '' before the comparison and calls
     * it what it is: not a wrong password, no password at all.
     */
    passwordFactor()->enroll(7, ['password' => 'correct horse battery staple']);

    expect(passwordFactor()->verify(new VerificationRequest(
        attempt: driverAttempt(),
        input: ['password' => ''],
    ))->failure)->toBe(FactorFailure::Malformed);
});

/*
 * "cannot verify against an attempt with no identified user" was deleted here.
 * It could not fail: Laravel compiles where('user_id', null) to
 * whereNull('user_id'), the credential lookup misses whether or not the
 * $userId === null guard exists, and the fallback returns NoCredential either
 * way — the same outcome the never-enrolled test above already pins. Making it
 * discriminate would need a credential row with a NULL user_id, which the schema
 * forbids.
 */
