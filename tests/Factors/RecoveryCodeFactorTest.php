<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Policy\PolicyParser;
use Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function recoveryFactor(): RecoveryCodeFactor
{
    return app(RecoveryCodeFactor::class);
}

function recoveryAttempt(?int $userId = 7): AuthAttempt
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

/** @return list<string> */
function enrollRecoveryCodes(int $userId = 7): array
{
    $result = recoveryFactor()->enroll($userId, []);

    return array_map(static fn ($secret): string => $secret->reveal(), $result->secrets);
}

it('carries recovery strength, which is what excludes it from policy', function (): void {
    expect(recoveryFactor()->strength())->toBe(FactorStrength::Recovery)
        ->and(recoveryFactor()->maxActiveCredentials())->toBe(10);
});

it('creates ten credentials and returns ten one-time secrets', function (): void {
    $result = recoveryFactor()->enroll(7, []);

    expect($result->credentials)->toHaveCount(10)
        ->and($result->secrets)->toHaveCount(10);
});

it('never stores a code in plaintext', function (): void {
    $codes = enrollRecoveryCodes();

    $stored = AuthCredential::where('user_id', 7)->pluck('secret')->all();

    foreach ($codes as $code) {
        expect($stored)->not->toContain($code);
    }
});

it('issues distinct codes', function (): void {
    $codes = enrollRecoveryCodes();

    expect(array_unique($codes))->toHaveCount(10);
});

it('satisfies with a valid code and returns exactly one disable mutation', function (): void {
    $codes = enrollRecoveryCodes();

    $result = recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[3]],
    ));

    expect($result->isSatisfied())->toBeTrue()
        ->and($result->mutations)->toHaveCount(1)
        ->and($result->mutations[0])->toBeInstanceOf(DisableCredential::class);
});

it('does not itself burn the code it matched', function (): void {
    /*
     * The whole reason single-use state belongs to the store. If the driver
     * disabled the credential here, a subsequent failed transition would leave
     * the code spent and the user unauthenticated.
     */
    $codes = enrollRecoveryCodes();

    recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[0]],
    ));

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(10);
});

it('burns the code only when the store commits the transition', function (): void {
    $codes = enrollRecoveryCodes();
    $attempt = recoveryAttempt();

    $result = recoveryFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $codes[0]],
    ));

    $outcome = app(AttemptStore::class)->transition(
        $attempt,
        AttemptState::FactorSatisfied,
        ...$result->mutations,
    );

    expect($outcome)->toBe(TransitionOutcome::Succeeded)
        ->and(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(9);
});

it('refuses a code that has already been spent', function (): void {
    $codes = enrollRecoveryCodes();
    $attempt = recoveryAttempt();

    $first = recoveryFactor()->verify(new VerificationRequest($attempt, ['code' => $codes[0]]));
    app(AttemptStore::class)->transition($attempt, AttemptState::FactorSatisfied, ...$first->mutations);

    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[0]],
    ))->failure)->toBe(FactorFailure::Mismatch);
});

it('regenerating invalidates every prior code', function (): void {
    $old = enrollRecoveryCodes();
    $new = enrollRecoveryCodes();

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(10)
        ->and(recoveryFactor()->verify(new VerificationRequest(
            attempt: recoveryAttempt(),
            input: ['code' => $old[0]],
        ))->failure)->toBe(FactorFailure::Mismatch)
        ->and(recoveryFactor()->verify(new VerificationRequest(
            attempt: recoveryAttempt(),
            input: ['code' => $new[0]],
        ))->isSatisfied())->toBeTrue();
});

it('cannot satisfy a policy, asserted through the kernel rather than the driver', function (): void {
    /*
     * The guard lives in SatisfiabilityEvaluator, which filters Recovery
     * explicitly rather than relying on strength ordering. Asserting it here
     * through the evaluator — not by reading the driver's own metadata — is what
     * makes this test worth having: a driver that lied about its strength would
     * still be caught by the evaluator, and this proves the evaluator is what
     * decides.
     */
    $codes = enrollRecoveryCodes();

    $result = recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => $codes[0]],
    ));

    // Narrows $result->factor to non-null for PHPStan via isSatisfied()'s
    // @phpstan-assert-if-true annotation; also fails the test loudly if the
    // valid code above did not verify.
    if (! $result->isSatisfied()) {
        throw new RuntimeException('Expected the recovery code to verify.');
    }

    $policy = (new PolicyParser())->parse(['any_of' => ['recovery_code', 'password']]);
    $verdict = (new SatisfiabilityEvaluator())->evaluate($policy, [$result->factor]);

    // Verdict exposes a public `satisfied` property, not a method.
    expect($verdict->satisfied)->toBeFalse();
});

it('reports malformed input rather than a mismatch', function (): void {
    enrollRecoveryCodes();

    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: [],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('reports an empty code as malformed, as every driver does', function (): void {
    /*
     * Hash::check('', $hashOfEmptyString) is TRUE — password_verify treats '' as
     * a real password — so an empty code must never reach the comparison loop.
     * Rejecting it also denies an attacker ten bcrypt comparisons per submission.
     */
    enrollRecoveryCodes();

    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => ''],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('reports a code of only separators as malformed, after normalisation', function (): void {
    // Codes are presented hyphenated, so the driver strips spaces and hyphens
    // before comparing. '  - - ' normalises to '' and must be caught THERE, not
    // by the raw-input check that precedes normalisation.
    enrollRecoveryCodes();

    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => '  - - '],
    ))->failure)->toBe(FactorFailure::Malformed);
});

it('reports no credential when the user has never enrolled', function (): void {
    expect(recoveryFactor()->verify(new VerificationRequest(
        attempt: recoveryAttempt(),
        input: ['code' => 'ABCDEFGHJK'],
    ))->failure)->toBe(FactorFailure::NoCredential);
});
