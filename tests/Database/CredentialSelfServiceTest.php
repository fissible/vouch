<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\SelfService\SelfServiceOutcome;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Tests\Support\InterceptingFactor;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

uses(DatabaseMigrations::class);

/*
 * 2.3d Task 4. Credential self-service.
 *
 * The capability matrix is the whole point, and it exists because "every
 * operation requires step-up" contradicts itself: AssuranceComparator fails
 * closed on ANY recovery-grace session, so a user in grace could never
 * regenerate codes or replace the factor they lost -- which is precisely what
 * grace is for. Grace capability is therefore a SEPARATE AXIS from the
 * assurance ladder, not a rung on it.
 *
 * DatabaseMigrations because factor removal revokes sessions under the
 * credential-change ordering contract, which is about COMMITS -- a
 * RefreshDatabase wrapper transaction would hide the distinction the
 * independent-connection probe below exists to draw.
 *
 * The sixth matrix row, minting API tokens, has no executable test here
 * because no token API exists yet. It is deferred to 2.4 as an explicit
 * acceptance criterion, so this file does not cover the full six-row matrix.
 */

function selfServiceUser(int $userId = 1, string $value = 'ada@acme.example'): AuthIdentifier
{
    $identifier = AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)
        ->enroll($userId, ['password' => 'old-password']);

    return $identifier;
}

/** A session that has stepped up: authenticated, not grace. */
function steppedUpSession(int $userId = 1, string $binding = 'step-up-1'): AuthSession
{
    return AuthSession::create([
        'user_id' => $userId,
        'session_binding' => str_pad($binding, 64, 'a'),
        'amr' => ['pwd', 'otp'],
        'acr' => 'aal2',
        // 2.4 Task 2a: authorization re-derives from the proof, so a fixture
        // that carried only a level now proves nothing and is refused.
        'assurance_proof' => sessionProof($userId, 'aal2'),
        'weakest_satisfied_at' => now(),
    ]);
}

/** An ordinary authenticated session that has NOT stepped up. */
function singleFactorSession(int $userId = 1, string $binding = 'single-1'): AuthSession
{
    return AuthSession::create([
        'user_id' => $userId,
        'session_binding' => str_pad($binding, 64, 'b'),
        'amr' => ['pwd'],
        'acr' => 'aal1',
        'assurance_proof' => sessionProof($userId, 'aal1'),
        'weakest_satisfied_at' => now(),
    ]);
}

/** A recovery-grace session: never sufficient for any assurance level. */
function graceSession(int $userId = 1, string $binding = 'grace-1'): AuthSession
{
    return AuthSession::create([
        'user_id' => $userId,
        'session_binding' => str_pad($binding, 64, 'c'),
        'amr' => ['recovery_code'],
        'acr' => null,
        // Deliberately proof-bearing: grace must be refused because it is grace,
        // not because it happens to lack evidence.
        'assurance_proof' => sessionProof($userId, 'aal2'),
        'weakest_satisfied_at' => now(),
        'recovery_grace_expires_at' => now()->addMinutes(15),
    ]);
}

function currentPassword(int $userId = 1): string
{
    return stringValue(AuthCredential::query()
        ->where('user_id', $userId)->where('type', 'password')
        ->whereNull('disabled_at')->value('secret'));
}

/* ---- the grace capability matrix -------------------------------------- */

it('lets a grace session regenerate recovery codes', function (): void {
    selfServiceUser();
    $grace = graceSession();

    /*
     * A user who spent their last code must be able to get more. Refusing this
     * is the deadlock the separate axis exists to prevent.
     */
    expect(app(CredentialSelfService::class)->regenerateRecoveryCodes($grace))
        ->toBe(SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->where('user_id', 1)
            ->where('type', 'recovery_code')->whereNull('disabled_at')->exists())->toBeTrue();
});

it('lets a grace session enroll a replacement second factor', function (): void {
    selfServiceUser();
    $grace = graceSession();

    // Replacing the factor they lost is the purpose of grace. Asserting only
    // the outcome would let a no-op Completed pass.
    expect(app(CredentialSelfService::class)
        ->addFactor($grace, 'totp', ['label' => 'ada@acme.example']))
        ->toBe(SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'totp')
            ->whereNull('disabled_at')->exists())->toBeTrue();
});

it('refuses a password change from a grace session', function (): void {
    selfServiceUser();
    $grace = graceSession();

    /*
     * Code control alone must not rewrite the primary credential. That is the
     * reset ceremony, which carries its own evidence rules.
     */
    /*
     * RecoveryRestricted, not StepUpRequired: grace cannot step up into
     * permission, so telling the user to step up sends them at a remedy that
     * does not exist. The two outcomes are different instructions.
     */
    expect(app(CredentialSelfService::class)->changePassword($grace, 'new-password'))
        ->toBe(SelfServiceOutcome::RecoveryRestricted)
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue();
});

it('refuses factor removal from a grace session', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $grace = graceSession();

    // Destructive, and it reduces future recovery options.
    expect(app(CredentialSelfService::class)->removeFactor($grace, $totp->id))
        ->toBe(SelfServiceOutcome::RecoveryRestricted)
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())
        ->toBeTrue();
});

it('refuses adding an identifier from a grace session', function (): void {
    selfServiceUser();
    $grace = graceSession();

    /*
     * Adding a delivery target during recovery is an account-takeover
     * primitive: it turns a recovered session into a permanent foothold.
     */
    expect(app(CredentialSelfService::class)->addIdentifier($grace, 'email', 'attacker@evil.test'))
        ->toBe(SelfServiceOutcome::RecoveryRestricted)
        ->and(AuthIdentifier::query()->where('value', 'attacker@evil.test')->exists())->toBeFalse();
});

/* ---- the assurance axis ------------------------------------------------ */

it('refuses every operation from a session that has not stepped up', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $single = singleFactorSession();
    $service = app(CredentialSelfService::class);

    /*
     * Each refusal is paired with the state it must NOT have changed. Without
     * that, an implementation could mutate and then return StepUpRequired.
     */
    expect($service->changePassword($single, 'new-password'))->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue()
        ->and($service->removeFactor($single, $totp->id))->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())->toBeTrue()
        ->and($service->addIdentifier($single, 'email', 'second@acme.example'))->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(AuthIdentifier::query()->where('value', 'second@acme.example')->exists())->toBeFalse()
        ->and($service->addFactor($single, 'totp', ['label' => 'x']))->toBe(SelfServiceOutcome::StepUpRequired)
        ->and($service->regenerateRecoveryCodes($single))->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')->exists())->toBeFalse();
});

it('permits every operation from a stepped-up session', function (): void {
    selfServiceUser();
    $stepped = steppedUpSession();
    $service = app(CredentialSelfService::class);

    /*
     * The positive control for the whole matrix. Without it, a service that
     * refused everything would satisfy every refusal test above.
     */
    $added = $service->addFactor($stepped, 'totp', ['label' => 'ada@acme.example']);
    $credential = AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->firstOrFail();

    expect($service->changePassword($stepped, 'new-password'))->toBe(SelfServiceOutcome::Completed)
        ->and(Hash::check('new-password', currentPassword()))->toBeTrue()
        ->and($added)->toBe(SelfServiceOutcome::Completed)
        ->and($service->regenerateRecoveryCodes($stepped))->toBe(SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')
            ->whereNull('disabled_at')->exists())->toBeTrue()
        ->and($service->addIdentifier($stepped, 'email', 'second@acme.example'))->toBe(SelfServiceOutcome::Completed)
        ->and($service->removeFactor($stepped, $credential->id))->toBe(SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->whereKey($credential->id)->whereNull('disabled_at')->exists())->toBeFalse();
});

/* ---- policy and ordering ---------------------------------------------- */

it('refuses to remove a factor the policy requires', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];

    \Fissible\Vouch\Models\AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['password', 'totp']],
        'posture' => 'friendly',
    ]);

    /*
     * Refused, not silently allowed: leaving a user unable to satisfy their own
     * policy is a lockout the package created.
     */
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id))
        ->toBe(SelfServiceOutcome::RequiredByPolicy)
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())
        ->toBeTrue();
});

it('revokes other sessions when a factor is removed', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $acting = steppedUpSession();
    $sibling = singleFactorSession(1, 'sibling');

    app(CredentialSelfService::class)->removeFactor($acting, $totp->id);

    /*
     * Under the credential-change ordering contract: other sessions end, the
     * acting session survives, and the reason is recorded.
     */
    expect(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())->toBeFalse()
        ->and($sibling->refresh()->revoked_at)->not->toBeNull()
        ->and($sibling->refresh()->revoked_reason)->toBe(RevokedReason::CredentialChanged)
        ->and($acting->refresh()->revoked_at)->toBeNull();
});

it('re-evaluates the acting session assurance after removing a factor', function (): void {
    /*
     * The session claimed aal2 on the strength of a factor that no longer
     * exists. Leaving the claim standing would let a removed factor keep
     * authorizing step-up-gated routes.
     *
     * 2.4 Task 2a changes what "the claim" IS. Before it, downgrading meant
     * writing acr = 'aal1' and authorization believed the column. Now
     * authorization re-derives from the persisted proof, so writing acr alone
     * downgrades nothing: the proof still names the removed credential and the
     * session still derives aal2. The evidence has to stop counting it.
     *
     * The proof here carries the REAL credential ids, because an implementation
     * cannot correlate a disabled credential with its factor otherwise. How it
     * responds -- rewriting the proof without that factor, or refusing factors
     * whose credential is no longer live -- is deliberately not specified; only
     * the outcome is.
     */
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $password = AuthCredential::query()->where('user_id', 1)->where('type', 'password')->firstOrFail();

    $acting = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('step-up-real', 64, 'a'),
        'amr' => ['password', 'totp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProofFrom(1, [
            evidenceFactor('password', '2026-08-13T10:00:00+00:00', FactorStrength::Knowledge, (string) $password->id),
            evidenceFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, (string) $totp->id),
        ]),
        'weakest_satisfied_at' => now(),
    ]);

    expect(usableEvidence($acting)->derivedAcr())->toBe('aal2');

    app(CredentialSelfService::class)->removeFactor($acting, $totp->id);

    $reloaded = $acting->refresh();
    $evidence = usableEvidence($reloaded);

    /*
     * Exact, not "not aal2": null, aal0 or garbage would all satisfy the looser
     * form while meaning entirely different things. Password remains, so the
     * session drops to aal1 -- and the evidence must agree, not merely the
     * column beside it.
     */
    expect($reloaded->acr)->toBe('aal1')
        ->and($evidence->derivedAcr())->toBe('aal1')
        ->and(array_map(static fn ($f): string => $f->credentialId, $evidence->factors))
        ->not->toContain((string) $totp->id);
});

it('starts a newly added identifier unverified', function (): void {
    selfServiceUser();

    app(CredentialSelfService::class)->addIdentifier(steppedUpSession(), 'email', 'second@acme.example');

    expect(AuthIdentifier::query()->where('value', 'second@acme.example')->value('verified_at'))
        ->toBeNull();
});

/* ---- authorization boundaries ----------------------------------------- */

it('refuses to remove another user\'s credential', function (): void {
    selfServiceUser(1);
    selfServiceUser(2, 'bob@acme.example');
    $bobsTotp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(2, ['label' => 'bob@acme.example'])->credentials[0];

    /*
     * Step-up authorizes operations on YOUR account. A service that checked
     * assurance but not ownership would let any stepped-up user strip factors
     * from any other.
     */
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(1), $bobsTotp->id))
        ->toBe(SelfServiceOutcome::Refused)
        ->and(AuthCredential::query()->whereKey($bobsTotp->id)->whereNull('disabled_at')->exists())
        ->toBeTrue();
});

it('refuses any operation from a revoked session', function (): void {
    selfServiceUser();
    $revoked = steppedUpSession();
    $revoked->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::Logout->value]);

    expect(app(CredentialSelfService::class)->changePassword($revoked, 'new-password'))
        ->toBe(SelfServiceOutcome::Refused)
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue();
});

it('refuses a grace capability that has already lapsed', function (): void {
    selfServiceUser();
    $grace = graceSession();

    /*
     * isRecoveryGrace() is true for any non-null deadline, including a past
     * one, so a service trusting the passed model rather than the authoritative
     * lookup would keep honoring an expired capability indefinitely.
     */
    /*
     * where('id', ...) rather than whereKey(): whereKey() is an Eloquent
     * Builder method, and on the Query Builder it falls through __call to a
     * dynamic where('key', ...) that matches no column and updates nothing.
     */
    DB::table('auth_sessions')->where('id', $grace->id)
        ->update(['recovery_grace_expires_at' => '2000-01-01 00:00:00']);

    expect(app(CredentialSelfService::class)->regenerateRecoveryCodes($grace->refresh()))
        ->toBe(SelfServiceOutcome::Refused)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')->exists())
        ->toBeFalse();
});

it('permits removing a factor the policy does not require', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];

    \Fissible\Vouch\Models\AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['password']],
        'posture' => 'friendly',
    ]);

    /*
     * The paired case for the policy refusal. Without it, an implementation
     * that simply always refuses totp removal passes that test.
     */
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id))
        ->toBe(SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())
        ->toBeFalse();
});

it('refuses an absent credential exactly as it refuses another user\'s', function (): void {
    selfServiceUser();

    /*
     * Pins the disclosure contract for the three-way outcome: Refused covers
     * both "not yours" and "does not exist", so a caller cannot probe which
     * credential ids are real. Ownership is only meaningful after session
     * validity and assurance have already been classified.
     */
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), 999_999))
        ->toBe(SelfServiceOutcome::Refused);
});

/* ---- the ordering contract, proven rather than observed ---------------- */

it('commits sibling revocation before disabling the factor', function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped('Proving the revocation COMMITTED needs a second connection.');
    }

    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $acting = steppedUpSession();
    $sibling = singleFactorSession(1, 'sibling');

    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $intercepted = new InterceptingFactor(
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class),
        beforeRevoke: fn (): bool => revokedOnAnotherConnection($sibling->id),
        throwOnRevoke: true,
    );
    $registry->register($intercepted);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $outcome = app(CredentialSelfService::class)->removeFactor($acting, $totp->id);

    /*
     * Read on a SEPARATE connection, so it proves the revocation COMMITTED
     * rather than merely ran first. The contract forbids sharing a transaction
     * precisely because a rollback would undo both, and a same-connection read
     * cannot tell the two arrangements apart.
     */
    expect($intercepted->observed)->toBeTrue()
        ->and($outcome)->toBe(SelfServiceOutcome::Refused)
        ->and($sibling->refresh()->revoked_at)->not->toBeNull()
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())->toBeTrue();
});

/**
 * Read revocation state through a genuinely separate connection.
 *
 * Falling back to Eloquent's default connection on MySQL or PostgreSQL would
 * not be independent, so it could not distinguish a committed revocation from
 * one still inside an open transaction -- which is the entire claim.
 */
function revokedOnAnotherConnection(int $sessionId): bool
{
    $default = Config::string('database.default');
    config(['database.connections.self_service_probe' => Config::array('database.connections.' . $default)]);

    return DB::connection('self_service_probe')
        ->table('auth_sessions')->where('id', $sessionId)->value('revoked_at') !== null;
}
