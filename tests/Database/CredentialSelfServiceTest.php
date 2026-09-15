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
use Fissible\Vouch\Tests\Support\InterceptingPasswordFactor;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
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
    expect(app(CredentialSelfService::class)->regenerateRecoveryCodes($grace)->outcome)
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
        ->addFactor($grace, 'totp', ['label' => 'ada@acme.example'])->outcome)
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
    expect(app(CredentialSelfService::class)->changePassword($grace, 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::RecoveryRestricted)
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue();
});

it('refuses factor removal from a grace session', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $grace = graceSession();

    // Destructive, and it reduces future recovery options.
    expect(app(CredentialSelfService::class)->removeFactor($grace, $totp->id)->outcome)
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
    expect(app(CredentialSelfService::class)->addIdentifier($grace, 'email', 'attacker@evil.test')->outcome)
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
    expect($service->changePassword($single, 'new-password')->outcome)->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue()
        ->and($service->removeFactor($single, $totp->id)->outcome)->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())->toBeTrue()
        ->and($service->addIdentifier($single, 'email', 'second@acme.example')->outcome)->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(AuthIdentifier::query()->where('value', 'second@acme.example')->exists())->toBeFalse()
        ->and($service->addFactor($single, 'totp', ['label' => 'x'])->outcome)->toBe(SelfServiceOutcome::StepUpRequired)
        ->and($service->regenerateRecoveryCodes($single)->outcome)->toBe(SelfServiceOutcome::StepUpRequired)
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

    expect($service->changePassword($stepped, 'new-password')->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and(Hash::check('new-password', currentPassword()))->toBeTrue()
        ->and($added->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($service->regenerateRecoveryCodes($stepped)->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')
            ->whereNull('disabled_at')->exists())->toBeTrue()
        ->and($service->addIdentifier($stepped, 'email', 'second@acme.example')->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($service->removeFactor($stepped, $credential->id)->outcome)->toBe(SelfServiceOutcome::Completed)
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
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id)->outcome)
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

    expect(nameOf(usableEvidence($acting)))->toBe('aal2');

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
        ->and(nameOf($evidence))->toBe('aal1')
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
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(1), $bobsTotp->id)->outcome)
        ->toBe(SelfServiceOutcome::Refused)
        ->and(AuthCredential::query()->whereKey($bobsTotp->id)->whereNull('disabled_at')->exists())
        ->toBeTrue();
});

it('refuses any operation from a revoked session', function (): void {
    selfServiceUser();
    $revoked = steppedUpSession();
    $revoked->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::Logout->value]);

    expect(app(CredentialSelfService::class)->changePassword($revoked, 'new-password')->outcome)
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

    expect(app(CredentialSelfService::class)->regenerateRecoveryCodes($grace->refresh())->outcome)
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
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id)->outcome)
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
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), 999_999)->outcome)
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
     *
     * #35 amended the expected value only. The ordering this test pins did not
     * change; the outcome stopped being spelled the same as an unauthorized
     * caller's refusal.
     */
    expect($intercepted->observed)->toBeTrue()
        ->and($outcome->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
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

/* ---- #35: what a failed mutation says after revocation committed ------- */

/*
 * The ordering pinned above stays. What changes is that a mutation failing
 * AFTER the revocation commit no longer answers with the same value as a
 * caller who was never authorized.
 *
 * Self-service and recovery share the ordering, so they share the vocabulary.
 * SelfServiceOutcome::CredentialChangeFailed is scoped precisely:
 *
 *   authorized; sibling sessions were revoked and committed;
 *   Vouch-owned credential writes rolled back.
 *
 * "Rolled back" is a requirement, not a description. A caught Throwable does
 * not prove the credential is unchanged, because the failure can land after the
 * driver already wrote -- measured, not assumed: only changePassword() rolled
 * back, because it alone runs its mutation inside CredentialMutation. So the
 * mutation phase runs in its own transaction, after and separate from the
 * revocation's committed one, and the post-write tests below force that.
 *
 * Two boundaries this outcome does NOT cross:
 *
 *   Additive addFactor() never revokes siblings -- it does not go through
 *   mutateCredentials() at all -- so its failures stay Refused. Extending the
 *   new outcome there would claim a revocation that never happened.
 *
 *   CredentialMutation runs token-issuer revocation in afterCommit, past the
 *   point any transaction can undo. A failure there is not a rollback and must
 *   not be reported as one: the credential DID change, and what is left is an
 *   unreconciled residual the result has to surface rather than swallow.
 *
 * The line these tests hold is WHERE the failure happened. mutateCredentials()
 * is the only place that revokes, so only failures inside it may use the new
 * value. Every refusal reached before it -- an unauthorized session, a lapsed
 * grace, a policy requirement, an unresolvable factor -- keeps its existing
 * value AND must leave live sessions alone. A rename of the catch block
 * satisfies neither half of any pair below.
 *
 * These outcomes are for the service caller and the operator. Nothing here
 * requires them on a public response body; a host that renders them outward
 * should keep an ordinary refusal's shape, because "our credential store threw"
 * is not the anonymous caller's business.
 */

/** Substitute a password factor whose enroll() throws inside the mutation. */
function failingPasswordFactor(): void
{
    $registry = new FactorRegistry();
    $registry->register(new InterceptingPasswordFactor(
        app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class),
        throw: true,
    ));

    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);
}

/** A registry that cannot resolve totp, so removeFactor fails BEFORE revoking. */
function registryWithoutTotp(): void
{
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));

    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);
}

it('distinguishes a credential change that failed from one that was refused', function (): void {
    selfServiceUser();
    failingPasswordFactor();

    $failed = app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password');

    // The same operation from a session that never stepped up. Refused before
    // anything was authorized, and it must not borrow the failure's value.
    $refused = app(CredentialSelfService::class)->changePassword(singleFactorSession(), 'new-password');

    expect($failed->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($failed->outcome)->not->toBe(SelfServiceOutcome::Refused)
        ->and($failed->outcome)->not->toBe(SelfServiceOutcome::Completed)
        ->and($refused->outcome)->toBe(SelfServiceOutcome::StepUpRequired);
});

it('leaves the credential usable when the change fails', function (): void {
    selfServiceUser();
    failingPasswordFactor();

    /*
     * The enum alone would accept an implementation that mutated and then
     * reported failure, which is the partial success this outcome exists to
     * rule out.
     */
    expect(app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue()
        ->and(Hash::check('new-password', currentPassword()))->toBeFalse();
});

it('leaves siblings revoked when the change fails', function (): void {
    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');
    failingPasswordFactor();

    /*
     * The revocation is not undone. It closed a real window, and reversing it
     * on failure would re-open exactly the one the ordering exists to shut.
     */
    expect(app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($sibling->refresh()->revoked_at)->not->toBeNull()
        ->and($sibling->refresh()->revoked_reason)->toBe(RevokedReason::PasswordChanged);
});

it('returns no secrets from a change that failed', function (): void {
    selfServiceUser();
    failingPasswordFactor();

    /*
     * Enrollment material cannot be re-read later, so a result that carries
     * secrets is a claim the enrollment happened. A failure must carry none.
     */
    $result = app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password');

    expect($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($result->secrets)->toBe([]);
});

it('keeps an ordinary refusal for a failure that precedes revocation', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $sibling = singleFactorSession(1, 'sibling');
    registryWithoutTotp();

    /*
     * removeFactor() resolves the driver BEFORE mutateCredentials(), so this
     * failure happens with no revocation behind it. Both halves matter: the
     * old value, and the untouched sibling. An implementation that revoked
     * first, or that renamed every caught Throwable, fails one or the other.
     */
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id)->outcome)
        ->toBe(SelfServiceOutcome::Refused)
        ->and($sibling->refresh()->revoked_at)->toBeNull()
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())->toBeTrue();
});

it('does not revoke siblings for a refusal the policy required', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $sibling = singleFactorSession(1, 'sibling');

    \Fissible\Vouch\Models\AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['password', 'totp']],
        'posture' => 'friendly',
    ]);

    // The third early exit, and the third that must leave live sessions alone.
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id)->outcome)
        ->toBe(SelfServiceOutcome::RequiredByPolicy)
        ->and($sibling->refresh()->revoked_at)->toBeNull();
});

it('cannot reach the failure outcome without authorization', function (): void {
    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');
    failingPasswordFactor();

    $revoked = steppedUpSession(1, 'revoked');
    $revoked->update(['revoked_at' => now(), 'revoked_reason' => RevokedReason::Logout->value]);

    $grace = graceSession();

    /*
     * The failure outcome is only produced past authorization, so no caller who
     * failed authorization can learn that the credential store is throwing. The
     * mutation is rigged to fail throughout: an implementation that revoked or
     * mutated before authorizing would surface CredentialChangeFailed here.
     */
    expect(app(CredentialSelfService::class)->changePassword($revoked, 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::Refused)
        ->and(app(CredentialSelfService::class)->changePassword(singleFactorSession(1, 'weak'), 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::StepUpRequired)
        ->and(app(CredentialSelfService::class)->changePassword($grace, 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::RecoveryRestricted)
        ->and($sibling->refresh()->revoked_at)->toBeNull()
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue();
});

it('reports the failure that produced the outcome', function (): void {
    Exceptions::fake();

    selfServiceUser();
    failingPasswordFactor();

    /*
     * No AuditSink driver exists yet (2.4), so report() IS the operator path.
     * The outcome tells the user to retry; this tells whoever runs the system
     * why there is anything to retry.
     */
    expect(app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::CredentialChangeFailed);

    /*
     * By identity, not by class: asserting RuntimeException alone would pass on
     * any unrelated reported exception.
     */
    Exceptions::assertReported(fn (RuntimeException $reported): bool =>
        $reported->getMessage() === 'Credential mutation failed after revocation committed.');
});

it('still reports a successful change as completed', function (): void {
    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');

    /*
     * The new case must not widen. A change that works keeps Completed, still
     * revokes siblings, and still changes the credential.
     */
    expect(app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::Completed)
        ->and(Hash::check('new-password', currentPassword()))->toBeTrue()
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

/* ---- #35: rollback is the promise, and its two boundaries ------------- */

/** A registry whose named factor throws AFTER its real write lands. */
function factorFailingAfterWrite(string $factorId): void
{
    $inner = match ($factorId) {
        'password' => app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class),
        'totp' => app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class),
        'recovery_code' => app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class),
        // Named rather than defaulted: a typo'd factor id would otherwise
        // silently wrap the password driver and test nothing it claims to.
        default => throw new RuntimeException('No double for factor ' . $factorId . '.'),
    };

    $registry = new FactorRegistry();
    if ($factorId !== 'password') {
        $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    }
    $registry->register(new InterceptingFactor($inner, throwAfterRevoke: true, throwAfterEnroll: true));

    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);
}

it('rolls back a password written before the failure', function (): void {
    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');

    // Captured before the attempt: a rollback restores THIS row, and an
    // implementation that compensates by rewriting the old hash into a new
    // active row leaves a different id behind.
    $original = AuthCredential::query()
        ->where('user_id', 1)->where('type', 'password')->firstOrFail();

    factorFailingAfterWrite('password');

    /*
     * The case a catch block cannot handle. Without a transaction around the
     * mutation phase, the outcome says "rolled back" while the account's
     * password has changed to a value the user never saw confirmed.
     *
     * The revocation committed in its own earlier transaction, so rolling the
     * mutation back must not take it along. An implementation that wrapped both
     * together fails the last assertion.
     */
    expect(app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password')->outcome)
        ->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue()
        ->and(Hash::check('new-password', currentPassword()))->toBeFalse()
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'password')->count())->toBe(1)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'password')
            ->whereNull('disabled_at')->count())->toBe(1)
        ->and(AuthCredential::query()->whereKey($original->id)->whereNull('disabled_at')->exists())
        ->toBeTrue()
        ->and(AuthCredential::query()->whereKey($original->id)->value('secret'))->toBe($original->secret)
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('restores the replaced credential when replacement fails after writing', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $sibling = singleFactorSession(1, 'sibling');
    $secret = AuthCredential::query()->whereKey($totp->id)->value('secret');
    factorFailingAfterWrite('totp');

    /*
     * Replacement disables the old credential and writes a new one, so a
     * half-applied replacement leaves the user with neither the authenticator
     * they had nor the one they were enrolling -- locked out of a factor by an
     * operation that reported failure.
     */
    $result = app(CredentialSelfService::class)
        ->addFactor(steppedUpSession(), 'totp', ['label' => 'ada@acme.example', 'replace' => true]);

    expect($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($result->secrets)->toBe([])
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())->toBeTrue()
        ->and(AuthCredential::query()->whereKey($totp->id)->value('secret'))->toBe($secret)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->count())->toBe(1)
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('restores the removed credential when removal fails after revoking', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $sibling = singleFactorSession(1, 'sibling');
    factorFailingAfterWrite('totp');

    /*
     * The removal counterpart. The existing ordering test injects its failure
     * BEFORE revoke() runs, so it cannot see a revocation that landed and was
     * then reported as failed.
     */
    expect(app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id)->outcome)
        ->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())->toBeTrue()
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('preserves the existing codes when regeneration fails after writing', function (): void {
    selfServiceUser();

    /*
     * Seeded deliberately. Starting from an empty set, "no codes exist"
     * passes against an implementation that deletes the old set before the
     * mutation transaction opens and never rolls that deletion back -- which
     * is the state that strands a user completely: told it failed, holding
     * codes that no longer authenticate.
     */
    $original = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials;
    $originalRows = AuthCredential::query()->where('user_id', 1)
        ->where('type', 'recovery_code')->orderBy('id')->get(['id', 'secret'])
        ->map(fn ($row): array => ['id' => $row->id, 'secret' => $row->secret])->all();

    $sibling = singleFactorSession(1, 'sibling');
    factorFailingAfterWrite('recovery_code');

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($result->secrets)->toBe([])
        /*
         * Secrets, not just ids. Surviving rows whose hashes were rewritten
         * carry the same ids and the same count while none of the codes the
         * user holds still authenticate -- measured as passing an id-and-count
         * assertion, so the hashes are the thing to compare.
         */
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')
            ->orderBy('id')->get(['id', 'secret'])
            ->map(fn ($row): array => ['id' => $row->id, 'secret' => $row->secret])->all())
        ->toBe($originalRows)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')
            ->whereNull('disabled_at')->count())->toBe(count($original))
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('revokes siblings when recovery codes are regenerated', function (): void {
    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');

    /*
     * Regeneration replaces a credential set, so it belongs with replacement
     * and removal rather than with additive enrollment: the old codes stop
     * authenticating, and a session resting on them must not continue. That it
     * bypassed the mutation facade was an incomplete writer migration, not a
     * decision -- and without this test an implementation can keep bypassing it
     * while still returning the new failure outcome.
     */
    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->not->toBe([])
        ->and($sibling->refresh()->revoked_at)->not->toBeNull()
        ->and($sibling->refresh()->revoked_reason)->toBe(RevokedReason::CredentialChanged);
});

it('keeps an additive enrollment failure an ordinary refusal', function (): void {
    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');

    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(new InterceptingPasswordFactor(
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class),
        throw: true,
    ));
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    /*
     * Additive enrollment never enters mutateCredentials(), so no revocation
     * pass ran. Returning CredentialChangeFailed here would assert a revocation
     * that did not happen -- the same species of false claim #35 exists to
     * remove, pointed the other way. Both halves are the test: the old value,
     * and the untouched sibling.
     */
    expect(app(CredentialSelfService::class)
        ->addFactor(steppedUpSession(), 'totp', ['label' => 'ada@acme.example'])->outcome)
        ->toBe(SelfServiceOutcome::Refused)
        ->and($sibling->refresh()->revoked_at)->toBeNull()
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->exists())->toBeFalse();
});

it('surfaces a driver revocation that failed past the point of rollback', function (): void {
    selfServiceUser();

    // A token whose recorded proof cites the password being replaced.
    app(\Fissible\Vouch\Tokens\TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-key-1',
        \Fissible\Vouch\Tokens\SubjectKey::forConfiguredUser(1),
        null,
        \Fissible\Vouch\Tokens\ActorKind::Human,
        [new \Fissible\Vouch\Kernel\Factor\SatisfiedFactor(
            'password',
            stringValue(AuthCredential::query()->where('user_id', 1)->where('type', 'password')->value('id')),
            \Fissible\Vouch\Kernel\Factor\FactorKind::Knowledge,
            FactorStrength::Knowledge,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        )],
    );

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
    );
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );
    app()->forgetInstance(CredentialSelfService::class);

    /*
     * CredentialMutation runs issuer revocation in afterCommit, deliberately
     * past the commit, so no transaction can undo it. This is NOT the rollback
     * case and must not borrow its outcome: the password really did change, so
     * the operation completed.
     *
     * What must not happen is a clean success. The token that cited the old
     * password may still be live at the issuer, and today that failure is
     * recorded on a CredentialMutationResult the service throws away -- nothing
     * in src/ reads driverFailures. The residual has to reach the caller.
     */
    $result = app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password');

    /*
     * attempted proves the contested path actually ran. Without it this test
     * could demand a residual the code has no way to produce, and would read as
     * a missing feature rather than an unreachable one.
     */
    expect($issuer->attempted)->toBe(['token-key-1'])
        ->and($issuer->revoked)->toBe([])
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and(Hash::check('new-password', currentPassword()))->toBeTrue()
        ->and($result->driverFailures)->not->toBe([])
        ->and($result->driverFailures[0]->issuerKey)->toBe('sanctum')
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1');

    expectPublicIdentityOnly($result->driverFailures);
});

it('reports no residual when driver revocation succeeds', function (): void {
    selfServiceUser();

    app(\Fissible\Vouch\Tokens\TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-key-1',
        \Fissible\Vouch\Tokens\SubjectKey::forConfiguredUser(1),
        null,
        \Fissible\Vouch\Tokens\ActorKind::Human,
        [new \Fissible\Vouch\Kernel\Factor\SatisfiedFactor(
            'password',
            stringValue(AuthCredential::query()->where('user_id', 1)->where('type', 'password')->value('id')),
            \Fissible\Vouch\Kernel\Factor\FactorKind::Knowledge,
            FactorStrength::Knowledge,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        )],
    );

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer('sanctum');
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );
    app()->forgetInstance(CredentialSelfService::class);

    /*
     * The paired negative. Without it, an implementation that always reports a
     * residual would pass the test above and tell every caller their tokens are
     * in doubt.
     */
    $result = app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password');

    expect($issuer->revoked)->toBe(['token-key-1'])
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->driverFailures)->toBe([]);
});

it('commits sibling revocation before changing a password', function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped('Proving the revocation COMMITTED needs a second connection.');
    }

    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');

    $factor = new InterceptingPasswordFactor(
        app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class),
        before: fn (): bool => revokedOnAnotherConnection($sibling->id),
        throw: true,
    );
    $registry = new FactorRegistry();
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    /*
     * The existing probe covers factor removal only. Wrapping the mutation
     * phase in a transaction is the change most likely to swallow the
     * revocation into it, and password change is the path that already had its
     * own CredentialMutation transaction -- so it is where a nested wrapper
     * would go wrong first.
     */
    $outcome = app(CredentialSelfService::class)->changePassword(steppedUpSession(), 'new-password');

    /*
     * observed is the ordering proof and must be read. The final-state check
     * below cannot tell "revoked first" from "revoked afterwards" -- both leave
     * the sibling revoked -- so without this assertion delayed revocation
     * passes, which is exactly what it did when measured.
     */
    expect($factor->observed)->toBeTrue()
        ->and($outcome->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and(revokedOnAnotherConnection($sibling->id))->toBeTrue()
        ->and(Hash::check('old-password', currentPassword()))->toBeTrue();
});

it('surfaces a driver residual when a replacement committed', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];

    // The proof cites the TOTP credential the replacement disables, so this
    // token is the one the mutation must ask the issuer to revoke.
    app(\Fissible\Vouch\Tokens\TokenAssuranceRecord::class)->store(
        'sanctum',
        'token-key-1',
        \Fissible\Vouch\Tokens\SubjectKey::forConfiguredUser(1),
        null,
        \Fissible\Vouch\Tokens\ActorKind::Human,
        [new \Fissible\Vouch\Kernel\Factor\SatisfiedFactor(
            'totp',
            (string) $totp->id,
            \Fissible\Vouch\Kernel\Factor\FactorKind::Possession,
            FactorStrength::Possession,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        )],
    );

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
    );
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );
    app()->forgetInstance(CredentialSelfService::class);

    /*
     * The residual is not a password-change feature. Every path that commits a
     * credential change can strand a token behind it, and an implementation
     * that carries the residual only out of changePassword() leaves the other
     * paths reporting a clean success they cannot vouch for -- measured as
     * surviving the previous round.
     */
    $result = app(CredentialSelfService::class)
        ->addFactor(steppedUpSession(), 'totp', ['label' => 'ada@acme.example', 'replace' => true]);

    expect($issuer->attempted)->toBe(['token-key-1'])
        ->and($issuer->revoked)->toBe([])
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->driverFailures)->not->toBe([])
        // Both identities. A residual carrying the right token under the wrong
        // issuer key sends an operator to the wrong system, and survived when
        // only the token key was asserted.
        ->and($result->driverFailures[0]->issuerKey)->toBe('sanctum')
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1');

    expectPublicIdentityOnly($result->driverFailures);
});

it('leaves siblings alone when an additive enrollment succeeds', function (): void {
    selfServiceUser();
    $sibling = singleFactorSession(1, 'sibling');

    /*
     * The paired positive for the additive boundary. Only the failure case was
     * pinned, so an implementation that routed additive enrollment through the
     * revoking path and mapped its outcome back to Refused still passed -- it
     * would log every other device out for adding a second factor, which is the
     * behavior the additive/revoking split exists to prevent.
     */
    $result = app(CredentialSelfService::class)
        ->addFactor(steppedUpSession(), 'totp', ['label' => 'ada@acme.example']);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($sibling->refresh()->revoked_at)->toBeNull()
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'totp')
            ->whereNull('disabled_at')->count())->toBe(1);
});

/**
 * A public residual names WHICH token at WHICH issuer, and nothing else.
 *
 * get_object_vars() from outside class scope sees public properties only.
 * json_encode() and print_r() can both be silenced -- by JsonSerializable and
 * __debugInfo -- while a public property still hands the driver's exception
 * text to the caller, which is why the property set is asserted directly.
 *
 * @param list<object> $failures
 */
function expectPublicIdentityOnly(array $failures): void
{
    foreach ($failures as $failure) {
        $properties = array_keys(get_object_vars($failure));
        sort($properties);

        // The SET is the contract; the declaration order is not. Comparing
        // unsorted would fail a correct implementation that declares tokenKey
        // first, which is a refusal this test has no business making.
        expect($properties)->toBe(['issuerKey', 'tokenKey']);
    }
}

/** Seed a human token whose recorded proof cites $credentialId of $type. */
function tokenCitingCredential(string $tokenKey, string $type, int $credentialId, string $issuerKey = 'sanctum'): void
{
    app(\Fissible\Vouch\Tokens\TokenAssuranceRecord::class)->store(
        $issuerKey,
        $tokenKey,
        \Fissible\Vouch\Tokens\SubjectKey::forConfiguredUser(1),
        null,
        \Fissible\Vouch\Tokens\ActorKind::Human,
        [new \Fissible\Vouch\Kernel\Factor\SatisfiedFactor(
            $type,
            (string) $credentialId,
            $type === 'password' ? \Fissible\Vouch\Kernel\Factor\FactorKind::Knowledge
                : \Fissible\Vouch\Kernel\Factor\FactorKind::Possession,
            $type === 'password' ? FactorStrength::Knowledge : FactorStrength::Possession,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        )],
    );
}

/** Register $issuer as the only token issuer. */
function onlyIssuer(\Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer $issuer): void
{
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );
    app()->forgetInstance(CredentialSelfService::class);
}

it('revokes tokens resting on the codes it regenerates', function (): void {
    selfServiceUser();
    $code = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials[0];
    tokenCitingCredential('token-key-1', 'recovery_code', $code->id);

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer('sanctum');
    onlyIssuer($issuer);

    /*
     * Sibling sessions are only half of what rests on a credential. A token
     * whose recorded proof cites a code being replaced is just as stale, and an
     * implementation that revokes sessions while leaving those tokens live
     * passed the entire suite when measured -- the regeneration reads as done
     * while an API client keeps authenticating on retired codes.
     */
    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($issuer->revoked)->toBe(['token-key-1'])
        ->and(DB::table('auth_token_assurances')->where('token_key', 'token-key-1')->exists())
        ->toBeFalse();
});

it('revokes siblings before regenerating, not after', function (): void {
    selfServiceUser();
    app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(1, []);
    $sibling = singleFactorSession(1, 'sibling');

    $factor = new InterceptingPasswordFactor(
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class),
        before: fn (): bool => AuthSession::query()->whereKey($sibling->id)->value('revoked_at') !== null,
        throw: true,
    );
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    /*
     * Final state cannot tell "revoked first" from "revoked in the catch
     * block": both leave the sibling revoked. Deferring regeneration's
     * revocation until the operation resolved passed all 84 tests when
     * measured, so the entry observation is the assertion that matters.
     *
     * Same-connection read, deliberately: this pins ORDER, which runs on every
     * engine. Commitment is pinned separately by the independent-connection
     * probes, which need a file-backed database.
     */
    app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($factor->observed)->toBeTrue()
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('surfaces a driver residual when a removal committed', function (): void {
    selfServiceUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    tokenCitingCredential('token-key-1', 'totp', $totp->id);

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
    );
    onlyIssuer($issuer);

    // Dropping any single operation's residual passed the whole suite when
    // measured, so each committing path carries its own case.
    $result = app(CredentialSelfService::class)->removeFactor(steppedUpSession(), $totp->id);

    expect($issuer->attempted)->toBe(['token-key-1'])
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->driverFailures)->not->toBe([])
        ->and($result->driverFailures[0]->issuerKey)->toBe('sanctum')
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1');

    expectPublicIdentityOnly($result->driverFailures);
});

it('surfaces a driver residual when a regeneration committed', function (): void {
    selfServiceUser();
    $code = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials[0];
    tokenCitingCredential('token-key-1', 'recovery_code', $code->id);

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
    );
    onlyIssuer($issuer);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($issuer->attempted)->toBe(['token-key-1'])
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->not->toBe([])
        ->and($result->driverFailures)->not->toBe([])
        ->and($result->driverFailures[0]->issuerKey)->toBe('sanctum')
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1')
        /*
         * Identities, not diagnostics -- print_r rather than json_encode,
         * because a JsonSerializable can hide a property the object still
         * exposes, and that mutant survived the JSON check alone.
         */
        ->and(print_r($result->driverFailures, true))->not->toContain('Issuer unreachable.');

    expectPublicIdentityOnly($result->driverFailures);
});

it('commits sibling revocation before regenerating codes', function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped('Proving the revocation COMMITTED needs a second connection.');
    }

    selfServiceUser();
    app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(1, []);
    $sibling = singleFactorSession(1, 'sibling');

    $factor = new InterceptingPasswordFactor(
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class),
        before: fn (): bool => revokedOnAnotherConnection($sibling->id),
        throw: true,
    );
    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register($factor);
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    /*
     * Regeneration needs its own commitment probe. The other paths' probes say
     * nothing about this one, and an implementation that revoked INSIDE the
     * mutation transaction and again after the rollback satisfied the
     * same-connection ordering test while never committing first -- measured as
     * passing all 88 tests and the whole suite.
     */
    $outcome = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($factor->observed)->toBeTrue()
        ->and($outcome->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and(revokedOnAnotherConnection($sibling->id))->toBeTrue();
});

it('keeps token invalidation committed when regeneration fails', function (): void {
    selfServiceUser();
    $code = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials[0];
    tokenCitingCredential('token-key-1', 'recovery_code', $code->id);

    factorFailingAfterWrite('recovery_code');

    /*
     * Token invalidation belongs to the revocation pass, so it commits with the
     * siblings and must survive the mutation's rollback for the same reason
     * they do. The credential-mapping rows go with it: leaving them behind
     * keeps a proof pointing at a code the invalidation already retired, and
     * that partial cleanup survived when only the assurance row was asserted.
     */
    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and(DB::table('auth_token_assurances')->where('token_key', 'token-key-1')->exists())
        ->toBeFalse()
        ->and(DB::table('auth_token_credentials')->where('token_key', 'token-key-1')->exists())
        ->toBeFalse();
});

it('reports a driver residual alongside a failed regeneration', function (): void {
    selfServiceUser();
    $code = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials[0];
    tokenCitingCredential('token-key-1', 'recovery_code', $code->id);

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
    );
    onlyIssuer($issuer);
    factorFailingAfterWrite('recovery_code');

    /*
     * The two are independent. Token invalidation committed with the revocation
     * pass, so its driver failure is real whether or not the credential
     * mutation then succeeded -- and an implementation that populates the
     * residual only on success hides it exactly when the operator most needs
     * it, while passing every success-path residual test.
     */
    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($issuer->attempted)->toBe(['token-key-1'])
        ->and($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($result->driverFailures)->not->toBe([])
        ->and($result->driverFailures[0]->issuerKey)->toBe('sanctum')
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1')
        /*
         * Rolled back means nothing to hand back. Returning the minted codes
         * only when a residual accompanies the rollback survived the whole
         * suite, and it is the worst shape: the user is told it failed while
         * holding codes that were written and then undone.
         */
        ->and($result->secrets)->toBe([]);

    expectPublicIdentityOnly($result->driverFailures);
});

it('names every token a regeneration could not clean up', function (): void {
    selfServiceUser();
    $code = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials[0];

    /*
     * Two issuers, one shared token key, and one token that cleans up fine.
     *
     * A token key is unique only WITHIN an issuer, so a residual keyed on the
     * token alone drops one of the two 'shared' entries and an operator leaves
     * the other live. Reporting the whole batch as failed instead sends them
     * after 'good', which was revoked correctly. Both survived every
     * same-issuer fixture.
     */
    tokenCitingCredential('shared', 'recovery_code', $code->id, 'alpha');
    tokenCitingCredential('shared', 'recovery_code', $code->id, 'beta');
    tokenCitingCredential('good', 'recovery_code', $code->id, 'alpha');

    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([
            failingOnSharedToken('alpha'),
            failingOnSharedToken('beta'),
        ]),
    );
    app()->forgetInstance(CredentialSelfService::class);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    // Pairs, not keys: the identity is (issuer, token) together.
    $pairs = array_map(
        fn (object $failure): array => [$failure->issuerKey, $failure->tokenKey],
        $result->driverFailures,
    );
    sort($pairs);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($pairs)->toBe([['alpha', 'shared'], ['beta', 'shared']]);
});

it('does not carry one change\'s residual into the next', function (): void {
    selfServiceUser();
    $code = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials[0];
    tokenCitingCredential('token-key-1', 'recovery_code', $code->id);

    // Throws on the FIRST revoke only, so the second call cleans up fully.
    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
        throwOnCall: 1,
    );
    onlyIssuer($issuer);

    $service = app(CredentialSelfService::class);

    $first = $service->regenerateRecoveryCodes(steppedUpSession());

    $replacement = AuthCredential::query()->where('user_id', 1)
        ->where('type', 'recovery_code')->whereNull('disabled_at')->firstOrFail();
    tokenCitingCredential('token-key-2', 'recovery_code', $replacement->id);

    $second = $service->regenerateRecoveryCodes(steppedUpSession(1, 'second'));

    /*
     * A residual accumulated on the service rather than built per call reports
     * the first failure again on every later call, sending an operator after a
     * token that was already reconciled. Same instance deliberately: resolving
     * a fresh one would hide it.
     */
    expect($first->driverFailures)->not->toBe([])
        ->and($second->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($second->driverFailures)->toBe([]);
});

it('invalidates the proof before asking the issuer to revoke it', function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped('Proving the invalidation COMMITTED needs a second connection.');
    }

    selfServiceUser();
    $code = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(1, [])->credentials[0];
    tokenCitingCredential('token-key-1', 'recovery_code', $code->id);

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer('sanctum');
    $issuer->onRevoke = fn (): array => [
        'assurance' => assuranceOnAnotherConnection('token-key-1'),
        'mapping' => mappingOnAnotherConnection('token-key-1'),
    ];
    onlyIssuer($issuer);

    /*
     * Vouch's own invalidation must be COMMITTED before the driver is asked to
     * revoke, or a driver failure leaves a proof that still cites a retired
     * credential with nothing recording that it should not. Calling the issuer
     * first survives the whole suite from the outside -- both orders end with
     * the rows gone -- so the only place the difference is visible is inside
     * the callback, read on a connection that cannot see an open transaction.
     */
    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes(steppedUpSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($issuer->observed)->toBe([['assurance' => false, 'mapping' => false]])
        /*
         * And still gone once the service returns. Observing the deletion from
         * inside the callback does not prove it stuck: restoring the mapping
         * rows afterwards satisfied the callback and the whole suite, leaving a
         * proof pointing at a credential the invalidation had retired.
         */
        ->and(DB::table('auth_token_assurances')->where('token_key', 'token-key-1')->exists())
        ->toBeFalse()
        ->and(DB::table('auth_token_credentials')->where('token_key', 'token-key-1')->exists())
        ->toBeFalse();
});

/** Does the assurance row still exist, read on a genuinely separate connection? */
function assuranceOnAnotherConnection(string $tokenKey): bool
{
    $default = Config::string('database.default');
    config(['database.connections.residual_probe' => Config::array('database.connections.' . $default)]);

    return DB::connection('residual_probe')
        ->table('auth_token_assurances')->where('token_key', $tokenKey)->exists();
}

/** The same question for the credential mappings that proof carries. */
function mappingOnAnotherConnection(string $tokenKey): bool
{
    $default = Config::string('database.default');
    config(['database.connections.residual_probe' => Config::array('database.connections.' . $default)]);

    return DB::connection('residual_probe')
        ->table('auth_token_credentials')->where('token_key', $tokenKey)->exists();
}
