<?php

declare(strict_types=1);

use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Secrets\OneTimeSecret;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\SelfService\SelfServiceOutcome;
use Illuminate\Foundation\Testing\DatabaseMigrations;

uses(DatabaseMigrations::class);

/*
 * Issue #32 -- self-service must return the secrets it mints.
 *
 * regenerateRecoveryCodes() called enroll() and threw away its return, which is
 * the ONLY copy of the plaintext: RecoveryCodeFactor::enroll() disables every
 * live recovery credential first, then returns OneTimeSecrets for the
 * replacements, which are hashed at rest.
 *
 * So the operation destroyed a working recovery set and replaced it with codes
 * nobody could ever read -- and a recovery-grace session can reach it, which is
 * exactly when recovery codes matter.
 *
 * The tests below care about one thing above all: not that a list comes back
 * non-empty, but that the codes a user is HANDED are the codes that work.
 */

function secretsUser(int $userId = 1): void
{
    AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)
        ->enroll($userId, ['password' => 'old-password']);
}

/** A session strong enough for self-service (which requires aal2). */
function secretsSession(int $userId = 1): AuthSession
{
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll($userId, ['label' => 'ada@acme.example']);

    $password = AuthCredential::query()->where('user_id', $userId)->where('type', 'password')->firstOrFail();
    $totp = AuthCredential::query()->where('user_id', $userId)->where('type', 'totp')->firstOrFail();

    return AuthSession::create([
        'user_id' => $userId,
        'session_binding' => str_pad('self-service-secrets', 64, 'c'),
        'amr' => ['password', 'totp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProofFrom($userId, [
            evidenceFactor('password', '2026-09-12T10:00:00+00:00', FactorStrength::Knowledge, (string) $password->id),
            evidenceFactor('totp', '2026-09-12T10:05:00+00:00', FactorStrength::Possession, (string) $totp->id),
        ]),
        'weakest_satisfied_at' => now(),
    ]);
}

/**
 * Reveal every secret once. reveal() is strictly single use -- a second call
 * throws -- so a test that wants the plaintext twice must capture it here.
 *
 * @param  list<OneTimeSecret>  $secrets
 * @return list<string>
 */
function revealAll(array $secrets): array
{
    return array_map(static fn (OneTimeSecret $secret): string => $secret->reveal(), $secrets);
}

function secretsAttempt(int $userId = 1): AuthAttempt
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

it('hands back a code that actually authenticates', function (): void {
    /*
     * THE test. Everything else here is bookkeeping around this: the user is
     * given codes, and those codes work against what was persisted. A list that
     * is merely non-empty would satisfy a weaker assertion while still handing
     * out the wrong values.
     */
    secretsUser();
    $session = secretsSession();

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);

    $codes = revealAll($result->secrets);

    expect($codes)->not->toBe([]);

    $verified = app(RecoveryCodeFactor::class)->verify(new VerificationRequest(
        attempt: secretsAttempt(),
        input: ['code' => $codes[0]],
    ));

    expect($verified->isSatisfied())->toBeTrue();
});

it('returns every minted code exactly once', function (): void {
    /*
     * A partial list is worse than none: the user stores what they were given
     * and finds the gap when they need it. The count is read from the stored
     * credentials rather than hard-coded, so a host that configures a different
     * number is not silently asserted against ten.
     */
    secretsUser();
    $session = secretsSession();

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);
    $codes = revealAll($result->secrets);

    $live = AuthCredential::query()
        ->where('user_id', 1)->where('type', 'recovery_code')->whereNull('disabled_at')->count();

    expect($codes)->toHaveCount($live)
        ->and(array_unique($codes))->toHaveCount(count($codes));
});

it('replaces the old set rather than adding to it', function (): void {
    /*
     * The destructive half, asserted so the returned codes are known to be the
     * ONLY ones that work -- not merely some that do.
     */
    secretsUser();
    $session = secretsSession();

    $service = app(CredentialSelfService::class);
    $first = revealAll($service->regenerateRecoveryCodes($session)->secrets);
    $service->regenerateRecoveryCodes($session->refresh());

    $verified = app(RecoveryCodeFactor::class)->verify(new VerificationRequest(
        attempt: secretsAttempt(),
        input: ['code' => $first[0]],
    ));

    expect($verified->isSatisfied())->toBeFalse();
});

it('returns the provisioning material when a factor is added', function (): void {
    // For TOTP that value carries the provisioning URI. Without it the user
    // cannot finish setting the authenticator up.
    secretsUser();
    $session = secretsSession();

    $result = app(CredentialSelfService::class)->addFactor($session->refresh(), 'totp', ['label' => 'ada@acme.example']);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->not->toBe([]);
});

it('returns no secrets from operations that mint none', function (): void {
    // Always, not usually: an empty list is the contract for these, so a
    // caller never has to know which methods can produce secrets.
    secretsUser();
    $session = secretsSession();

    $service = app(CredentialSelfService::class);

    expect($service->changePassword($session, 'a-new-password')->secrets)->toBe([])
        ->and($service->addIdentifier($session->refresh(), 'email', 'grace@acme.example')->secrets)->toBe([]);
});

it('returns no secrets when the operation is refused', function (): void {
    /*
     * There is nothing to reveal, and an empty list says so without the caller
     * having to test the outcome first. The session here is too weak for
     * self-service, which is the ordinary refusal.
     */
    secretsUser();
    $weak = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('weak-self-service', 64, 'd'),
        'amr' => ['password'],
        'acr' => 'aal1',
        'assurance_proof' => sessionProof(1, 'aal1'),
        'weakest_satisfied_at' => now(),
    ]);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($weak);

    expect($result->outcome)->not->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->toBe([]);
});

it('does not leak plaintext through the result object', function (): void {
    /*
     * The result must not become a second place the plaintext lives. These are
     * the accidental paths OneTimeSecret was built to survive -- var_export()
     * reads raw properties and consults none of the redacting hooks -- and
     * wrapping secrets in a new object is exactly how that containment gets
     * lost.
     */
    secretsUser();
    $session = secretsSession();

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    /*
     * Render BEFORE revealing. reveal() is single use, so the order matters:
     * these renderings must be taken while the secrets are still live, which is
     * precisely the state a stray dump would catch them in.
     */
    $renderings = [
        var_export($result, true),
        (string) json_encode($result),
        serialize($result),
        print_r($result, true),
    ];

    $codes = revealAll($result->secrets);

    // Without this the loop below iterates nothing and the test passes while
    // proving nothing -- which is what an earlier version of it did.
    expect($codes)->not->toBe([]);

    foreach ($renderings as $rendered) {
        foreach ($codes as $code) {
            expect($rendered)->not->toContain($code);
        }
    }
});
