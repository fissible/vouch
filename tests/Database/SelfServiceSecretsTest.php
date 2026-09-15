<?php

declare(strict_types=1);

use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
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
use Fissible\Vouch\SelfService\SelfServiceResult;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Tests\Support\CapturingFactor;
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

/**
 * A session strong enough for self-service, which requires aal2.
 *
 * @param  string  $second  The factor standing beside the password. 'totp' for
 *                          most tests; 'email_otp' where the test needs TOTP to
 *                          be ABSENT, since adding a factor that is already
 *                          enrolled is refused by the driver's own limit -- a
 *                          fixture that overlooked this made the additive case
 *                          reject a correct implementation.
 */
function secretsSession(int $userId = 1, string $second = 'totp'): AuthSession
{
    if ($second === 'totp') {
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
            ->enroll($userId, ['label' => 'ada@acme.example']);
    } else {
        app(EmailOtpFactor::class)->enroll($userId, [
            // identifier_id, not value: the driver requires an integer id of an
            // existing verified identifier and throws otherwise, which would
            // have failed this fixture before it reached self-service at all.
            'identifier_id' => (int) AuthIdentifier::query()->where('user_id', $userId)->firstOrFail()->id,
        ]);
    }

    $password = AuthCredential::query()->where('user_id', $userId)->where('type', 'password')->firstOrFail();
    $totp = AuthCredential::query()->where('user_id', $userId)->where('type', $second)->firstOrFail();

    return AuthSession::create([
        'user_id' => $userId,
        'session_binding' => str_pad('self-service-secrets', 64, 'c'),
        'amr' => ['password', 'totp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProofFrom($userId, [
            evidenceFactor('password', '2026-09-12T10:00:00+00:00', FactorStrength::Knowledge, (string) $password->id),
            evidenceFactor($second, '2026-09-12T10:05:00+00:00', FactorStrength::Possession, (string) $totp->id),
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

/**
 * Every returned code authenticates, and between them they account for every
 * stored credential -- no omissions, no duplicates.
 *
 * @param  list<string>  $codes
 * @return list<string>  the credential ids the codes matched
 */
function verifyEveryCode(array $codes): array
{
    $matched = [];

    foreach ($codes as $code) {
        $verified = app(RecoveryCodeFactor::class)->verify(new VerificationRequest(
            attempt: secretsAttempt(),
            input: ['code' => $code],
        ));

        expect($verified->isSatisfied())->toBeTrue("a returned code did not authenticate: {$code}");

        $matched[] = (string) ($verified->mutations[0]->credentialId ?? '');
    }

    return $matched;
}

/**
 * @param  list<string>  $matched
 */
function assertCoversEveryPersistedCode(array $matched, int $userId = 1): void
{
    $persisted = AuthCredential::query()
        ->where('user_id', $userId)->where('type', 'recovery_code')->whereNull('disabled_at')
        ->get()->map(static fn (AuthCredential $credential): string => (string) $credential->id)
        ->all();

    sort($matched);
    sort($persisted);

    /*
     * BOTH sides cast to string. DisableCredential carries an integer id while
     * the column plucks as int too, but the two have differed by type across
     * engines, and toBe() is strict -- [1,2] against ["1","2"] fails identity
     * and would reject a correct implementation.
     */
    expect($persisted)->not->toBe([])
        ->and($matched)->toBe($persisted);
}

/**
 * The returned provisioning URI drives the credential that was persisted.
 *
 * Derives a live code from the URI's own seed and verifies it, which is the
 * only check that distinguishes the right material from a well-formed string.
 */
function assertProvisionsTheStoredCredential(string $uri, int $userId = 1): void
{
    expect($uri)->toContain('otpauth://');

    parse_str((string) parse_url($uri, PHP_URL_QUERY), $query);
    $seed = is_string($query['secret'] ?? null) ? $query['secret'] : '';

    // A guard rather than an expectation: the seed has to be non-empty before
    // it can drive a TOTP at all, and the failure reads the same either way.
    if ($seed === '') {
        throw new RuntimeException('the returned provisioning URI carries no secret');
    }

    $credential = AuthCredential::query()
        ->where('user_id', $userId)->where('type', 'totp')->whereNull('disabled_at')->firstOrFail();

    $verified = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->verify(new VerificationRequest(
        attempt: secretsAttempt($userId),
        input: ['code' => \OTPHP\TOTP::createFromSecret($seed)->now()],
        credential: $credential,
    ));

    expect($verified->isSatisfied())->toBeTrue('the returned provisioning material does not drive the stored credential');
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

    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($codes)->not->toBe([]);

    /*
     * EVERY code, not the first. An implementation that returned one working
     * code followed by garbage satisfies a single-code check while handing the
     * user a set that mostly does not work -- and they would not find out until
     * they needed it.
     *
     * verify() returns a pending mutation rather than consuming the code, so
     * each verification is independent and the matched credential ids can be
     * collected.
     */
    $matched = verifyEveryCode($codes);

    /*
     * And each code matched a DIFFERENT stored credential. Without this, a set
     * of ten copies of one working code passes everything above.
     */
    assertCoversEveryPersistedCode($matched);
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

    /*
     * The non-zero guard is load-bearing: with no stored rows and an empty
     * list, toHaveCount(0) and array_unique([]) both pass and the test proves
     * nothing at all.
     */
    expect($live)->toBeGreaterThan(0)
        ->and($codes)->toHaveCount($live)
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

    $second = $service->regenerateRecoveryCodes($session->refresh());
    $replacements = revealAll($second->secrets);

    expect($second->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($replacements)->not->toBe([]);

    // EVERY old code, not the first: disabling one and leaving nine live is a
    // far worse outcome than the one this test was written to catch.
    foreach ($first as $stale) {
        $verified = app(RecoveryCodeFactor::class)->verify(new VerificationRequest(
            attempt: secretsAttempt(),
            input: ['code' => $stale],
        ));

        expect($verified->isSatisfied())->toBeFalse("a superseded code still authenticates: {$stale}");
    }

    /*
     * And the replacements ALL work and account for the whole stored set -- an
     * implementation that returned every code on first enrollment but truncated
     * on replacement would otherwise escape here.
     */
    assertCoversEveryPersistedCode(verifyEveryCode($replacements));
});

it('returns the provisioning material when a factor is added', function (): void {
    /*
     * The ADDITIVE branch, which needs TOTP to be absent -- the session's second
     * factor is an email OTP instead. An earlier fixture enrolled TOTP and then
     * added it again, which the driver refuses, so the test would have rejected
     * a correct implementation.
     */
    secretsUser();
    $session = secretsSession(second: 'email_otp');

    $capturing = new CapturingFactor(app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class));
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(app(EmailOtpFactor::class));
    $registry->register($capturing);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);

    $result = app(CredentialSelfService::class)->addFactor($session->refresh(), 'totp', ['label' => 'ada@acme.example']);

    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->not->toBe([]);

    /*
     * Exactly one secret, and it is the DRIVER'S OWN instance. A working value
     * is not enough: an implementation could reveal the URI, log it, and return
     * a fresh wrapper around the same string -- which still provisions the
     * credential and still renders safely, while the secret has already leaked.
     * Identity is what rules that out, and single-secret TOTP needs it as much
     * as the ten-secret recovery path.
     */
    expect($result->secrets)->toHaveCount(1)
        ->and($capturing->captured)->not->toBeNull()
        ->and($result->secrets)->toBe($capturing->enrollment()->secrets);

    assertProvisionsTheStoredCredential(revealAll($result->secrets)[0]);
});

it('returns the provisioning material when a factor is replaced', function (): void {
    // The other branch. addFactor() discards the driver's return in BOTH, so
    // covering one leaves half the defect live.
    secretsUser();
    $session = secretsSession();

    $capturing = new CapturingFactor(app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class));
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register($capturing);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);

    $result = app(CredentialSelfService::class)
        ->addFactor($session->refresh(), 'totp', ['label' => 'ada@acme.example', 'replace' => true]);

    // Identity on this branch too -- reveal-log-rewrap is available to both.
    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->toHaveCount(1)
        ->and($capturing->captured)->not->toBeNull()
        ->and($result->secrets)->toBe($capturing->enrollment()->secrets);

    assertProvisionsTheStoredCredential(revealAll($result->secrets)[0]);
});

it('returns no secrets from operations that mint none', function (): void {
    // Always, not usually: an empty list is the contract for these, so a
    // caller never has to know which methods can produce secrets.
    secretsUser();
    $session = secretsSession();

    $service = app(CredentialSelfService::class);

    /*
     * The OUTCOMES are asserted too. Without them both operations could simply
     * be refusing, and an empty secret list on a refusal proves nothing about
     * a method that mints none on success.
     */
    $password = $service->changePassword($session, 'a-new-password');
    $identifier = $service->addIdentifier($session->refresh(), 'email', 'grace@acme.example');

    expect($password->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($password->secrets)->toBe([])
        ->and($identifier->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($identifier->secrets)->toBe([]);
});

it('returns no secrets from a successful removal', function (): void {
    // removeFactor() was missing from the secretless set, and it is the method
    // most likely to grow one later.
    secretsUser();
    $session = secretsSession();
    app(EmailOtpFactor::class)->enroll(1, [
        'identifier_id' => (int) AuthIdentifier::query()->where('user_id', 1)->firstOrFail()->id,
    ]);

    $totp = AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->firstOrFail();

    $result = app(CredentialSelfService::class)->removeFactor($session->refresh(), $totp->id);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->toBe([]);
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

it('does not leak provisioning material through the result object', function (): void {
    /*
     * The same containment for TOTP, and the SEED is checked separately from
     * the URI. JSON escaping can hide a full `otpauth://` substring while
     * leaving the secret itself readable, so matching only the whole URI would
     * miss exactly the part that matters.
     */
    secretsUser();
    $session = secretsSession(second: 'email_otp');

    $result = app(CredentialSelfService::class)->addFactor($session->refresh(), 'totp', ['label' => 'ada@acme.example']);

    $renderings = [
        var_export($result, true),
        (string) json_encode($result),
        serialize($result),
        print_r($result, true),
    ];

    $uri = revealAll($result->secrets)[0];
    parse_str((string) parse_url($uri, PHP_URL_QUERY), $query);
    $seed = is_string($query['secret'] ?? null) ? $query['secret'] : '';

    expect($seed)->not->toBe('');

    foreach ($renderings as $rendered) {
        expect($rendered)->not->toContain($uri)
            ->and($rendered)->not->toContain($seed);
    }
});

it('returns usable codes to a recovery-grace session', function (): void {
    /*
     * The case the defect hurts most: a user who has lost a factor, is inside
     * the grace window, and regenerates. Existing grace coverage asserts the
     * outcome and the persisted rows -- neither of which notices that the user
     * was handed nothing.
     */
    secretsUser();
    $grace = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('grace-secrets', 64, 'e'),
        'amr' => ['recovery_code'],
        'acr' => null,
        'assurance_proof' => null,
        'weakest_satisfied_at' => null,
        'recovery_grace_expires_at' => now()->addMinutes(10),
    ]);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($grace);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed);

    $codes = revealAll($result->secrets);

    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($codes)->not->toBe([]);

    // The same completeness check as the ordinary path: truncation during
    // grace is exactly as harmful and would otherwise go unnoticed.
    assertCoversEveryPersistedCode(verifyEveryCode($codes));
});

it('hands a grace session the provisioning material for its replacement factor', function (): void {
    /*
     * Grace is a separate authorization path, so an implementation could
     * forward secrets everywhere else and return none here -- leaving a user
     * who has already lost a factor with a credential they cannot enroll and
     * no way to recover it. Existing grace coverage asserts the outcome and the
     * persisted row, neither of which notices an empty list.
     */
    secretsUser();
    $grace = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('grace-addfactor', 64, 'e'),
        'amr' => ['recovery_code'],
        'acr' => null,
        'assurance_proof' => null,
        'weakest_satisfied_at' => null,
        'recovery_grace_expires_at' => now()->addMinutes(10),
    ]);

    $result = app(CredentialSelfService::class)->addFactor($grace, 'totp', ['label' => 'ada@acme.example']);

    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->toHaveCount(1);

    assertProvisionsTheStoredCredential(revealAll($result->secrets)[0]);
});

it('returns a result, never a bare outcome, from every method', function (): void {
    /*
     * §3k makes the shape uniform, and property access alone would accept any
     * object that happens to expose ->outcome. Asserting the named type across
     * all five is what makes "uniform" a contract rather than a coincidence.
     */
    secretsUser();
    $session = secretsSession(second: 'email_otp');
    $service = app(CredentialSelfService::class);

    $totp = $service->addFactor($session->refresh(), 'totp', ['label' => 'ada@acme.example']);
    $credential = AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->firstOrFail();

    foreach ([
        $service->changePassword($session->refresh(), 'a-new-password'),
        $service->addIdentifier($session->refresh(), 'email', 'grace@acme.example'),
        $service->regenerateRecoveryCodes($session->refresh()),
        $totp,
        $service->removeFactor($session->refresh(), $credential->id),
    ] as $result) {
        expect($result)->toBeInstanceOf(SelfServiceResult::class);
    }
});

it('returns a result with no secrets when authorization refuses', function (): void {
    // A refusal is still a result. Returning a bare enum on the failure path
    // would make every caller branch on type before reading an outcome.
    secretsUser();
    $weak = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('weak-typed', 64, 'f'),
        'amr' => ['password'],
        'acr' => 'aal1',
        'assurance_proof' => sessionProof(1, 'aal1'),
        'weakest_satisfied_at' => now(),
    ]);

    $service = app(CredentialSelfService::class);

    foreach ([
        $service->regenerateRecoveryCodes($weak),
        $service->addFactor($weak, 'totp', ['label' => 'x']),
        $service->changePassword($weak, 'another-password'),
    ] as $result) {
        expect($result)->toBeInstanceOf(SelfServiceResult::class)
            ->and($result->outcome)->not->toBe(SelfServiceOutcome::Completed)
            ->and($result->secrets)->toBe([]);
    }
});

it('returns no secrets when enrollment itself fails', function (): void {
    /*
     * An enrollment that never happens, distinct from an authorization
     * refusal. Named precisely: the driver throws BEFORE minting anything, so
     * this is not the after-mint case -- that one has its own test below,
     * because they fail in different places and only one of them has secrets
     * in hand at the moment it fails.
     */
    secretsUser();
    $session = secretsSession();

    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(new CapturingFactor(
        app(RecoveryCodeFactor::class),
        onEnroll: static fn () => throw new RuntimeException('enrollment exploded'),
    ));
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    /*
     * #35: regeneration replaces a credential set, so it revokes siblings and
     * commits that before mutating. A failure past that commit is no longer
     * spelled the same as an unauthorized caller's refusal. The empty-secrets
     * assertion is the point of these tests and is unchanged.
     */
    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($result->secrets)->toBe([]);
});

it('hands back the driver\'s own secret instances, not copies of them', function (): void {
    /*
     * The containment gap the rendering tests cannot see. A service that
     * revealed each secret, logged it, and wrapped the value in a fresh
     * OneTimeSecret would satisfy every assertion about the rendered result --
     * while having already leaked the plaintext on the way through.
     *
     * Identity is the only thing that distinguishes forwarding from
     * revealing-and-rewrapping.
     */
    secretsUser();
    $session = secretsSession();

    $capturing = new CapturingFactor(app(RecoveryCodeFactor::class));
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register($capturing);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    expect($capturing->captured)->not->toBeNull()
        ->and($result->secrets)->toBe($capturing->enrollment()->secrets);
});

it('returns no secrets when the operation fails after minting them', function (): void {
    /*
     * The other failure: material EXISTS by the time things go wrong. The
     * driver has minted and the throw happens before enroll() RETURNS, so the
     * service never receives the result -- which means this covers a failure
     * with secrets in existence, NOT one after the service has captured them.
     * The latter needs a seam inside the service and is recorded as a gap
     * rather than claimed here.
     */
    secretsUser();
    $session = secretsSession();

    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(new CapturingFactor(
        app(RecoveryCodeFactor::class),
        onEnrolled: static fn () => throw new RuntimeException('failed after minting'),
    ));
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    /*
     * #35: regeneration replaces a credential set, so it revokes siblings and
     * commits that before mutating. A failure past that commit is no longer
     * spelled the same as an unauthorized caller's refusal. The empty-secrets
     * assertion is the point of these tests and is unchanged.
     */
    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($result->secrets)->toBe([]);
});

it('forwards every secret, and the driver\'s own instances, when a factor is added', function (): void {
    /*
     * Both of round 3's gaps in one test, because they are the same gap seen
     * twice.
     *
     * TOTP returns ONE secret, so every addFactor test so far passes against an
     * implementation that returns `$enrollment->secrets[0]`. Recovery codes
     * return ten, which is what makes truncation visible.
     *
     * And identity was only ever checked through regenerateRecoveryCodes, so
     * addFactor could reveal, log and rewrap while its returned values still
     * authenticated and its result still rendered safely.
     */
    secretsUser();
    $session = secretsSession();

    $capturing = new CapturingFactor(app(RecoveryCodeFactor::class));
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class));
    $registry->register($capturing);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);

    $result = app(CredentialSelfService::class)->addFactor($session->refresh(), 'recovery_code', []);

    /*
     * Completed is load-bearing, not decoration. Without it an implementation
     * could return Refused CARRYING the secrets and satisfy every other
     * assertion here, which is precisely the "failed operations return no
     * secrets" rule inverted.
     */
    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($capturing->captured)->not->toBeNull()
        ->and(count($capturing->enrollment()->secrets))->toBeGreaterThan(1)
        ->and($result->secrets)->toBe($capturing->enrollment()->secrets);

    // Still revealable, so the service did not read them on the way through.
    expect(revealAll($result->secrets))->toHaveCount(count($capturing->enrollment()->secrets));
});

it('forwards every secret when a factor is replaced', function (): void {
    // The replacing branch takes a different path through mutateCredentials,
    // so covering one branch says nothing about the other.
    secretsUser();
    $session = secretsSession();

    $capturing = new CapturingFactor(app(RecoveryCodeFactor::class));
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class));
    $registry->register($capturing);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);

    $result = app(CredentialSelfService::class)
        ->addFactor($session->refresh(), 'recovery_code', ['replace' => true]);

    expect($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($capturing->captured)->not->toBeNull()
        ->and(count($capturing->enrollment()->secrets))->toBeGreaterThan(1)
        ->and($result->secrets)->toBe($capturing->enrollment()->secrets);

    /*
     * Identity alone is not enough here. A replacement path could reveal the
     * codes -- logging them on the way -- and return those SAME wrappers, now
     * spent. They would still be the driver's instances and still pass every
     * assertion above, while the user receives ten objects that throw when
     * read. Revealing them here is the proof they are unspent.
     */
    expect(revealAll($result->secrets))->toHaveCount(count($capturing->enrollment()->secrets));
});

it('returns a typed, secretless result from an authorization refusal', function (): void {
    /*
     * Named for what it covers: weak-session AUTHORIZATION refusal across three
     * more methods. Not every downstream refusal -- policy and driver refusals
     * reach the same return but by other paths, and this does not exercise
     * them. The refusal tests elsewhere inspect only ->outcome, so those paths
     * could return any outcome-bearing object, or a result carrying secrets,
     * and pass.
     */
    secretsUser();
    $weak = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('weak-every-path', 64, 'g'),
        'amr' => ['password'],
        'acr' => 'aal1',
        'assurance_proof' => sessionProof(1, 'aal1'),
        'weakest_satisfied_at' => now(),
    ]);

    $service = app(CredentialSelfService::class);

    foreach ([
        $service->addIdentifier($weak, 'email', 'grace@acme.example'),
        $service->removeFactor($weak, 1),
        $service->addFactor($weak, 'recovery_code', ['replace' => true]),
    ] as $result) {
        expect($result)->toBeInstanceOf(SelfServiceResult::class)
            ->and($result->outcome)->not->toBe(SelfServiceOutcome::Completed)
            ->and($result->secrets)->toBe([]);
    }
});
