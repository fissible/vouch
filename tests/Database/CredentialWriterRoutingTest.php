<?php

declare(strict_types=1);

use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use OTPHP\TOTP;
use Illuminate\Database\ConnectionInterface;

uses(DatabaseMigrations::class);

/*
 * 2.4 Task 5b — the writers, through their REAL paths.
 *
 * The facade's own contract is pinned in tests/Tokens/CredentialMutationTest.php,
 * but a facade nobody calls protects nothing: every one of the sixteen measured
 * write sites could remain un-routed while that file stayed green, because it
 * invokes the facade directly with inert closures.
 *
 * This file drives the actual operations — a real authentication flow, real
 * factor drivers, real self-service — and asserts what happens to real
 * assurance-bound tokens. It is the file that fails if the routing is wrong,
 * and the routing is the task.
 *
 * DatabaseMigrations rather than RefreshDatabase, following
 * CredentialSelfServiceTest: the ordering contract is about COMMITS, and a
 * wrapper transaction hides exactly the distinction being drawn.
 */

function routingSubject(int $userId = 7): SubjectKey
{
    return SubjectKey::of(configuredUserProvider(), (string) $userId);
}

function routingIssuer(): RecordingIssuer
{
    $issuer = new RecordingIssuer('sanctum');
    app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([$issuer]));

    return $issuer;
}

/** @param list<string> $credentialIds */
function routingToken(string $tokenKey, array $credentialIds, int $userId = 7): void
{
    $factors = [];
    foreach ($credentialIds as $index => $credentialId) {
        $factors[] = new SatisfiedFactor(
            $index === 0 ? 'password' : 'totp',
            $credentialId,
            $index === 0 ? FactorKind::Knowledge : FactorKind::Possession,
            $index === 0 ? FactorStrength::Knowledge : FactorStrength::Possession,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        );
    }

    app(TokenAssuranceRecord::class)->store(
        'sanctum', $tokenKey, routingSubject($userId), null, ActorKind::Human, $factors,
    );
}

/** @return list<string> */
function routingSurvivors(): array
{
    $keys = DB::table('auth_token_assurances')->orderBy('token_key')->pluck('token_key')->all();

    return array_values(array_map(stringValue(...), $keys));
}

function routingUser(int $userId = 7, string $value = 'ada@acme.example'): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

function routingBinding(): string
{
    return str_repeat('r', 64);
}

/**
 * Begin a flow and return its handle.
 *
 * FlowResult is a marker INTERFACE — not every result carries a handle, and
 * annotating one onto it to satisfy a test would assert something false about
 * every other implementation. Narrowed to the concrete continuing result here
 * instead, which is where the handle actually lives.
 */
function routingBegin(): string
{
    $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], routingBinding()));

    if (! $begun instanceof Continuing || $begun->handle === null) {
        throw new RuntimeException('The flow did not begin with a continuing handle.');
    }

    return $begun->handle;
}

/** Drive the real flow to a TOTP submission, the way a host would. */
function routingAuthenticateWithTotp(string $password, string $code): void
{
    $handle = routingBegin();

    app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], routingBinding()));
    app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', ['password' => $password], routingBinding()));
    // 'submit', NOT 'recover'. AuthFlow forcibly selects recovery_code for the
    // recover action, so a recover here would never reach TotpFactor and the
    // engagement assertion below it would be asserting nothing.
    app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', ['code' => $code], routingBinding()));
}

/**
 * Every credential row that matters to atomicity, in a comparable shape.
 *
 * @return list<array{id: int, type: string, secret: string, disabled: bool}>
 */
function routingCredentialState(): array
{
    $rows = [];

    foreach (AuthCredential::query()->orderBy('id')->get() as $credential) {
        $rows[] = [
            'id' => (int) $credential->id,
            'type' => stringValue($credential->type),
            'secret' => stringValue($credential->secret),
            'disabled' => $credential->disabled_at !== null,
        ];
    }

    return $rows;
}

/** Give a credential a token that cites it, and hand the credential back. */
function routingCited(AuthCredential $credential): AuthCredential
{
    routingToken('cites-it', [stringValue($credential->id)]);

    return $credential;
}

function routingIdentifierId(int $userId = 7): int
{
    return (int) AuthIdentifier::query()->where('user_id', $userId)->firstOrFail()->id;
}

function routingTotpCode(int $userId = 7): string
{
    $secret = stringValue(AuthCredential::query()
        ->where('user_id', $userId)->where('type', 'totp')->firstOrFail()->secret);

    if ($secret === '') {
        throw new RuntimeException('The enrolled TOTP credential has no secret.');
    }

    // Built the way the DRIVER builds it — the container clock into OTPHP,
    // exactly as TotpFactor::matchTimestep() does.
    return TOTP::createFromSecret($secret, app(\Psr\Clock\ClockInterface::class))->now();
}

/** A session that has stepped up, so self-service will act on it. */
function routingSteppedUpSession(int $userId = 7): \Fissible\Vouch\Models\AuthSession
{
    return \Fissible\Vouch\Models\AuthSession::create([
        'user_id' => $userId,
        'session_binding' => str_pad('routing-step-up', 64, 'a'),
        'amr' => ['pwd', 'otp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProof($userId, 'aal2'),
        'weakest_satisfied_at' => now(),
    ]);
}

/* ---- the bookkeeping write, which is the whole reason for the task ------ */

it('does not revoke anything when a TOTP verification advances its timestep', function (): void {
    /*
     * THE test. TotpFactor::verify() emits AdvanceCredentialTimestep, and
     * DatabaseAttemptStore::apply() writes it to the credential row — the same
     * method, and the same table, as DisableCredential. It fires on EVERY
     * successful verification, because it is the replay guard.
     *
     * A facade that routed "every credential write" through the revoking path
     * would make every TOTP login revoke the user's own tokens. Driven through
     * the real AuthFlow with a real code, because the whole risk is that the
     * classification is right in the facade and wrong at the call site.
     */
    AuthPolicy::query()->create([
        'tenant_id' => null,
        'scope' => 'authenticate',
        'document' => ['all_of' => ['password', 'totp']],
        'posture' => 'friendly',
    ]);
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    $totp = app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0];

    routingToken('cites-the-totp', ['103', stringValue($totp->id)]);
    $issuer = routingIssuer();

    $before = AuthCredential::query()->whereKey($totp->id)->value('last_used_timestep');
    $secretBefore = stringValue(AuthCredential::query()->findOrFail($totp->id)->secret);
    routingAuthenticateWithTotp('correct horse battery staple', routingTotpCode());
    $after = AuthCredential::query()->whereKey($totp->id)->value('last_used_timestep');

    // The bookkeeping write really happened; otherwise this proves nothing.
    expect($after)->not->toBe($before)
        ->and($after)->not->toBeNull();

    /*
     * And it advanced the marker ONLY. Growing this already-counted update to
     * rewrite `secret` too would keep the statement count, the dispatch pin,
     * the manifest entry and both assertions above intact, while turning a
     * replay marker into a credential replacement with assurance left live.
     * Structural pins cannot see inside an arm; this can.
     */
    expect(stringValue(AuthCredential::query()->findOrFail($totp->id)->secret))->toBe($secretBefore);

    expect(routingSurvivors())->toBe(['cites-the-totp'])
        ->and($issuer->revoked)->toBe([]);
});

it('does not revoke anything when a recovery code is consumed', function (): void {
    /*
     * The SECOND bookkeeping trap in the same file, and the more dangerous of
     * the two because of what it is called.
     *
     * DatabaseAttemptStore::apply() handles DisableCredential, and the only
     * thing in the package that emits it is RecoveryCodeFactor's successful
     * verification burning the single-use code. So `DisableCredential` fires as
     * part of a SUCCESSFUL RECOVERY VERIFICATION, not as a revocation — despite the name, which
     * is exactly why classifying by identifier rather than by behaviour is
     * unsafe here.
     *
     * It is CONSUMPTION BOOKKEEPING. Being precise about what it is not: a
     * valid recovery code yields RecoveryGraceStarted rather than an ordinary
     * login, the HTTP handler deliberately does not log into the host guard,
     * and recovery-only evidence cannot be token assurance at all — so the
     * cited-token record below is SYNTHETIC, standing in for a token that
     * cites a credential which later gets burned by some other path.
     *
     * The rule it pins is still the one that matters: burning a single-use
     * credential during verification is not a revocation event, and a facade
     * that treated DisableCredential as revoking because of its name would act
     * on the wrong signal. That is the TOTP trap by a second route, and worse,
     * because here the identifier argues for the wrong answer.
     */
    AuthPolicy::query()->create([
        'tenant_id' => null,
        'scope' => 'authenticate',
        'document' => ['any_of' => ['password', 'recovery_code']],
        'posture' => 'friendly',
    ]);
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    $enrolled = app(RecoveryCodeFactor::class)->enroll(7, []);
    /*
     * The plaintext codes come back as OneTimeSecret objects — shown once,
     * stored only as hashes — so the test reveals one here, the way
     * AuthFlowTest's own recovery test does.
     */
    $code = $enrolled->secrets[0]->reveal();
    $credential = $enrolled->credentials[0];

    $secretBefore = stringValue($credential->secret);
    routingToken('cites-the-recovery-code', [stringValue($credential->id)]);
    $issuer = routingIssuer();

    $handle = routingBegin();
    app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], routingBinding()));
    // 'recover', not 'submit': burning a code is the recovery action, and the
    // flow hands the driver's DisableCredential to the store rather than
    // burning it itself.
    app(AuthFlow::class)->advance(new FlowRequest($handle, 'recover', ['code' => $code], routingBinding()));

    // Engagement: the code really was burned, so this is not passing because
    // the verification failed and nothing happened at all.
    $burned = AuthCredential::query()->where('user_id', 7)->where('type', 'recovery_code')
        ->whereNotNull('disabled_at')->pluck('id')->all();

    /*
     * Consumption DISABLES and does nothing else. Asserted because the arm-set
     * pin cannot see inside an arm: extending this already-counted update to
     * rewrite `secret` as well would keep the same arm set, the same single
     * statement and the same manifest entry, turning a password-changing
     * credential-secret replacement into one classified as bookkeeping with
     * assurance records left live. This row is a recovery-code credential, not
     * a password; the secret is what separates a use-marker from a replacement
     * whatever the credential type.
     */
    expect(stringValue(AuthCredential::query()->findOrFail($credential->id)->secret))
        ->toBe($secretBefore);

    expect($burned)->toHaveCount(1)
        ->and(stringValue($burned[0]))->toBe(stringValue($credential->id))
        ->and(routingSurvivors())->toBe(['cites-the-recovery-code'])
        ->and($issuer->revoked)->toBe([]);
});

/* ---- the revoking writers ----------------------------------------------- */

it('revokes tokens citing a credential when the factor driver disables it', function (): void {
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $password = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();

    routingToken('cites-password', [stringValue($password->id)]);
    routingToken('cites-other', ['888']);
    $issuer = routingIssuer();

    app(PasswordFactor::class)->revoke($password);

    // Engagement: the credential really was disabled. Otherwise this passes for
    // an implementation that invalidates tokens and never writes the row.
    expect(AuthCredential::query()->whereKey($password->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['cites-other'])
        ->and($issuer->revoked)->toBe(['cites-password']);
});

it('revokes on TOTP removal, the same path a user takes to drop a factor', function (): void {
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $totp = app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0];

    routingToken('cites-totp', [stringValue($totp->id)]);
    $issuer = routingIssuer();

    app(TotpFactor::class)->revoke($totp);

    expect(AuthCredential::query()->whereKey($totp->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe([])
        ->and($issuer->revoked)->toBe(['cites-totp']);
});

it('revokes on OTP credential removal', function (): void {
    /*
     * OtpFactor is a writer the detector finds and the earlier draft of this
     * file did not cover, so broken routing here would have shipped green.
     * Same shape as the others, different driver — which is the point: the
     * classification is per SITE, and each driver is its own site.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    // OtpFactor is abstract; EmailOtpFactor is the concrete driver the
    // container binds, and it inherits the write site under review.
    $otp = app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => routingIdentifierId()])->credentials[0];

    routingToken('cites-otp', [stringValue($otp->id)]);
    $issuer = routingIssuer();

    app(EmailOtpFactor::class)->revoke($otp);

    expect(AuthCredential::query()->whereKey($otp->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe([])
        ->and($issuer->revoked)->toBe(['cites-otp']);
});

it('revokes when a user removes a factor through self-service', function (): void {
    /*
     * The path a real user takes, as opposed to calling a driver directly.
     * CredentialSelfService already owns a mutation ordering contract for
     * SESSIONS; token invalidation has to join it rather than run beside it.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $totp = app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0];

    routingToken('cites-totp', [stringValue($totp->id)]);
    routingToken('cites-other', ['888']);
    $issuer = routingIssuer();

    $outcome = app(CredentialSelfService::class)
        ->removeFactor(routingSteppedUpSession(), (int) $totp->id);

    expect($outcome)->toBe(\Fissible\Vouch\SelfService\SelfServiceOutcome::Completed)
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['cites-other'])
        ->and($issuer->revoked)->toBe(['cites-totp']);
});

it('revokes on direct recovery-code revocation', function (): void {
    /*
     * RecoveryCodeFactor::revoke() is its own write site, separate from the
     * bulk disable that regeneration performs. Regeneration passing says
     * nothing about this path: they are different statements, and the whole
     * classification is per site.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $codes = app(RecoveryCodeFactor::class)->enroll(7, [])->credentials;

    routingToken('cites-a-code', [stringValue($codes[0]->id)]);
    routingToken('cites-another', [stringValue($codes[1]->id)]);
    $issuer = routingIssuer();

    app(RecoveryCodeFactor::class)->revoke($codes[0]);

    expect(AuthCredential::query()->whereKey($codes[0]->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['cites-another'])
        ->and($issuer->revoked)->toBe(['cites-a-code']);
});

/* ---- additive writers ---------------------------------------------------- */

it('preserves tokens when a first credential is enrolled for a new user', function (): void {
    /*
     * FirstCredentialEnrollment is the fifth measured writer, and it is
     * additive by definition: a subject acquiring its FIRST credential cannot
     * invalidate a proof, and another subject's tokens are not its business.
     */
    routingUser(8, 'grace@acme.example');
    // Subject 9 is the one being mutated, so subject 9 holds the token. A token
    // belonging to somebody else survives a feature that revokes far too much.
    routingToken('same-subject-token', ['777'], 9);
    $issuer = routingIssuer();

    app(\Fissible\Vouch\Enrollment\FirstCredentialEnrollment::class)->enroll(
        new \Fissible\Vouch\Enrollment\FirstCredentialRequest(
            userId: 9,
            identifierType: 'email',
            identifierValue: 'new@acme.example',
            password: 'a-first-password',
            tenantId: null,
            clientIp: '203.0.113.10',
        ),
    );

    // Feature engagement: the enrollment really created a credential. Without
    // this, a no-op enrollment preserves the other subject's token and passes.
    expect(AuthCredential::query()->where('user_id', 9)->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['same-subject-token'])
        ->and($issuer->revoked)->toBe([]);
});

it('preserves tokens when a new factor is enrolled', function (): void {
    /*
     * Enrolling TOTP must not log out every API client. An existing proof
     * cites credentials that still exist and still mean what they meant.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $password = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();

    routingToken('existing', [stringValue($password->id)]);
    $issuer = routingIssuer();

    app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    expect(AuthCredential::query()->where('user_id', 7)->where('type', 'totp')
        ->whereNull('disabled_at')->count())->toBe(1)
        ->and(routingSurvivors())->toBe(['existing'])
        ->and($issuer->revoked)->toBe([]);
});

it('revokes when a password is REPLACED, not only when it is revoked', function (): void {
    /*
     * A different branch of the same file. PasswordFactor::enroll(replace: true)
     * disables the old credential and creates a new one in one call, and that
     * disable is a revoking write even though the entry point is called
     * "enroll". Covering revoke() alone would leave this classified by
     * inference rather than by test.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $old = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();

    routingToken('cites-old-password', [stringValue($old->id)]);
    $issuer = routingIssuer();

    app(PasswordFactor::class)->enroll(7, ['password' => 'a-new-password', 'replace' => true]);

    expect(AuthCredential::query()->whereKey($old->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(AuthCredential::query()->where('user_id', 7)->where('type', 'password')
            ->whereNull('disabled_at')->count())->toBe(1)
        ->and(routingSurvivors())->toBe([])
        ->and($issuer->revoked)->toBe(['cites-old-password']);
});

it('revokes when a TOTP secret is REPLACED', function (): void {
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $old = app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0];

    routingToken('cites-old-totp', [stringValue($old->id)]);
    $issuer = routingIssuer();

    app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example', 'replace' => true]);

    expect(AuthCredential::query()->whereKey($old->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(AuthCredential::query()->where('user_id', 7)->where('type', 'totp')
            ->whereNull('disabled_at')->count())->toBe(1)
        ->and(routingSurvivors())->toBe([])
        ->and($issuer->revoked)->toBe(['cites-old-totp']);
});

it('preserves tokens when a disabled OTP credential is reactivated', function (): void {
    /*
     * OtpFactor's odd branch: enrolling over a DISABLED credential sets
     * disabled_at back to null rather than creating a row. It is additive by
     * the settled rule — a credential becoming live again falsifies no existing
     * proof — but it writes the same column a revocation writes, which is
     * exactly the kind of site a classification by inference gets wrong.
     */
    routingUser();
    $password = app(PasswordFactor::class)->enroll(7, ['password' => 'old-password'])->credentials[0];

    /*
     * The token and the issuer are installed BEFORE the initial OTP create, so
     * that branch is observed too — enrolling the first OTP credential for a
     * subject must not revoke that subject's existing tokens either. The token
     * cites the subject's password credential, which stays live throughout.
     */
    routingToken('same-subject-token', [stringValue($password->id)]);
    $issuer = routingIssuer();

    $otp = app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => routingIdentifierId()])->credentials[0];
    expect(routingSurvivors())->toBe(['same-subject-token'])
        ->and($issuer->revoked)->toBe([]);

    app(EmailOtpFactor::class)->revoke($otp);
    // The revoke above targets the OTP credential; the password token is not
    // cited by it and must remain.
    expect(routingSurvivors())->toBe(['same-subject-token']);

    app(EmailOtpFactor::class)->enroll(7, ['identifier_id' => routingIdentifierId()]);

    expect(AuthCredential::query()->whereKey($otp->id)->whereNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['same-subject-token'])
        ->and($issuer->revoked)->toBe([]);
});

/* ---- replacement coalescing --------------------------------------------- */

it('preserves tokens on a first recovery-code enrollment', function (): void {
    /*
     * The no-prior-codes branch, which is a pure create and therefore additive.
     * RecoveryCodeFactor::enroll() ignores its $data entirely -- there is no
     * `replace` flag -- so "first enrollment" and "regeneration" are the same
     * entry point taking different branches on what already exists. Both have
     * to be driven; neither can be inferred from the other.
     */
    routingUser();
    $password = app(PasswordFactor::class)->enroll(7, ['password' => 'old-password'])->credentials[0];

    // Same subject, distinct live credential: see the password-create test.
    routingToken('same-subject-token', [stringValue($password->id)]);
    $issuer = routingIssuer();

    $codes = app(RecoveryCodeFactor::class)->enroll(7, [])->credentials;

    // Persisted, not merely returned: a driver that built objects and never
    // wrote them would satisfy a non-empty array.
    expect(AuthCredential::query()->where('user_id', 7)->where('type', 'recovery_code')
        ->whereNull('disabled_at')->count())->toBe(count($codes))
        ->and($codes)->not->toBeEmpty()
        ->and(routingSurvivors())->toBe(['same-subject-token'])
        ->and($issuer->revoked)->toBe([]);
});

it('revokes exactly once when recovery codes are regenerated', function (): void {
    /*
     * Regeneration disables ten credentials and creates ten more. Treated as
     * separate mutations it revokes on the removal and again on the creation:
     * the user punished twice for one action, and the second pass sweeping
     * tokens the first had already replaced.
     *
     * Counted at the DRIVER, because "the tokens are gone" is equally true of
     * one revocation and of two.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $codes = app(RecoveryCodeFactor::class)->enroll(7, [])->credentials;

    routingToken('cites-a-code', [stringValue($codes[0]->id)]);
    $issuer = routingIssuer();

    // No flag: a second enrollment IS the regeneration, disabling every active
    // code and creating a fresh set inside one serialized closure.
    app(RecoveryCodeFactor::class)->enroll(7, []);

    // Old set disabled AND a fresh set created: a regeneration that only
    // disabled would revoke correctly and leave the user with no codes.
    expect(AuthCredential::query()->whereKey($codes[0]->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(AuthCredential::query()->where('user_id', 7)->where('type', 'recovery_code')
            ->whereNull('disabled_at')->count())->toBe(count($codes))
        ->and(routingSurvivors())->toBe([])
        ->and($issuer->attempted)->toBe(['cites-a-code']);
});

it('preserves tokens on an ordinary password enrollment', function (): void {
    /*
     * PasswordFactor's non-replacement create, which the replacement test does
     * not exercise: enroll() takes a different branch when there is nothing to
     * disable, and a branch classified by inference is a branch nobody checked.
     */
    routingUser();

    /*
     * The token must belong to the SUBJECT BEING MUTATED, citing a different
     * live credential. Holding another subject's token would pass for a feature
     * that wrongly revoked everything belonging to user 7 — the additive rule
     * is about this subject's own tokens surviving.
     */
    $totp = app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0];
    routingToken('same-subject-token', [stringValue($totp->id)]);
    $issuer = routingIssuer();

    app(PasswordFactor::class)->enroll(7, ['password' => 'a-first-password']);

    expect(AuthCredential::query()->where('user_id', 7)->where('type', 'password')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['same-subject-token'])
        ->and($issuer->revoked)->toBe([]);
});

it('sweeps the subject when first-credential enrollment reuses a disabled password row', function (): void {
    /*
     * FirstCredentialEnrollment's other branch, and the one place I got the
     * classification wrong before codex caught it.
     *
     * When a disabled password credential exists it does NOT create a row: it
     * reuses that row, writing a NEW SECRET and clearing disabled_at. I first
     * classified it revoking() -- non-additive, which is right -- but the
     * distinguishing fact is that it writes a new password secret, and the
     * settled rule for a password change is a SUBJECT-WIDE sweep of human
     * tokens, not precise revocation of whatever cited that one credential.
     *
     * The difference is observable, which is why this test asserts it: under
     * revoking(), a human token citing an UNRELATED credential would survive.
     * It must not.
     *
     * The contrast with OTP reactivation stands and is the reason the two
     * branches are classified differently: OTP re-enables an UNCHANGED
     * credential, so a proof citing it stays true.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $password = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
    $oldSecret = $password->secret;
    app(PasswordFactor::class)->revoke($password);

    routingToken('cites-the-reused-row', [stringValue($password->id)]);
    routingToken('cites-something-else', ['888']);
    app(TokenAssuranceRecord::class)->store(
        'sanctum', 'machine-token', routingSubject(), null, ActorKind::Machine, [],
    );
    $issuer = routingIssuer();

    app(\Fissible\Vouch\Enrollment\FirstCredentialEnrollment::class)->enroll(
        new \Fissible\Vouch\Enrollment\FirstCredentialRequest(
            userId: 7,
            identifierType: 'email',
            identifierValue: 'ada-again@acme.example',
            password: 'a-replacement-password',
            tenantId: null,
            clientIp: '203.0.113.10',
        ),
    );

    $reused = AuthCredential::query()->findOrFail($password->id);

    // Engagement: the same row, re-enabled, carrying a DIFFERENT secret. Without
    // the secret assertion this passes for a branch that merely re-enabled.
    expect($reused->disabled_at)->toBeNull()
        ->and($reused->secret)->not->toBe($oldSecret)
        ->and(AuthCredential::query()->where('user_id', 7)->where('type', 'password')->count())->toBe(1);

    // Subject-wide, human only: the unrelated human token goes too, the machine
    // token stays. Under precise revocation the second would have survived.
    expect(routingSurvivors())->toBe(['machine-token'])
        ->and($issuer->revoked)->toBe(['cites-something-else', 'cites-the-reused-row']);
});

/* ---- the subject-wide sweep --------------------------------------------- */

it('sweeps human tokens on a password change and leaves machine tokens alone', function (): void {
    /*
     * The contract boundary, driven through CredentialSelfService rather than
     * the facade: a machine token's authority never came from the password, and
     * Vouch does not authorize machine tokens this phase. Revoking one here
     * would break service-to-service traffic during a routine user action.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);

    routingToken('human-one', ['101']);
    routingToken('human-two', ['102']);
    app(TokenAssuranceRecord::class)->store(
        'sanctum', 'machine-token', routingSubject(), null, ActorKind::Machine, [],
    );
    $issuer = routingIssuer();

    $session = routingSteppedUpSession();
    $old = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
    app(CredentialSelfService::class)->changePassword($session, 'a-new-password');

    // Engagement: the password really changed, so the sweep is not being
    // credited for an operation that did nothing.
    expect(AuthCredential::query()->whereKey($old->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['machine-token'])
        ->and($issuer->revoked)->toBe(['human-one', 'human-two']);
});


/* ---- atomicity: the write must be INSIDE the facade's transaction -------- */

/*
 * Every revoking and subject-wide writer, proven to hand its ACTUAL credential
 * write to the facade rather than performing it beforehand.
 *
 * Without this, a writer could mutate auth_credentials on its own and call the
 * facade afterwards: the end state of every other test in this file would be
 * identical, and the mutation would not be atomic. A failure between the two
 * would leave a disabled or replaced credential whose tokens still authorize —
 * the precise state this task exists to make impossible.
 *
 * The failure is induced by removing the mapping table the invalidation must
 * write, which throws inside the facade's transaction. TokenAssuranceRecord is
 * final, so it cannot be doubled; this fails at the same place for the same
 * reason and needs no seam. DatabaseMigrations restores the schema.
 *
 * The discriminating assertion is the credential row: a write performed inside
 * the transaction is rolled back with it, and one performed beforehand survives.
 *
 * Each case enrolls its own credential and gives it a citing token, because a
 * mutation whose credential no token cites would invalidate nothing and never
 * reach the failure.
 */
dataset('revoking writers', [
    // arrange(): create the credential and a token citing it, return the credential.
    // mutate(): perform the writer's real operation on it.
    'password revoke' => [
        fn (): AuthCredential => routingCited(AuthCredential::query()
            ->where('user_id', 7)->where('type', 'password')->firstOrFail()),
        fn (AuthCredential $c) => app(PasswordFactor::class)->revoke($c),
    ],
    'password replace' => [
        fn (): AuthCredential => routingCited(AuthCredential::query()
            ->where('user_id', 7)->where('type', 'password')->firstOrFail()),
        fn (AuthCredential $c) => app(PasswordFactor::class)
            ->enroll(7, ['password' => 'a-new-password', 'replace' => true]),
    ],
    'totp revoke' => [
        fn (): AuthCredential => routingCited(
            app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0]),
        fn (AuthCredential $c) => app(TotpFactor::class)->revoke($c),
    ],
    'totp replace' => [
        fn (): AuthCredential => routingCited(
            app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0]),
        fn (AuthCredential $c) => app(TotpFactor::class)
            ->enroll(7, ['label' => 'ada@acme.example', 'replace' => true]),
    ],
    'recovery revoke' => [
        fn (): AuthCredential => routingCited(
            app(RecoveryCodeFactor::class)->enroll(7, [])->credentials[0]),
        fn (AuthCredential $c) => app(RecoveryCodeFactor::class)->revoke($c),
    ],
    'recovery regenerate' => [
        fn (): AuthCredential => routingCited(
            app(RecoveryCodeFactor::class)->enroll(7, [])->credentials[0]),
        fn (AuthCredential $c) => app(RecoveryCodeFactor::class)->enroll(7, []),
    ],
    'otp revoke' => [
        fn (): AuthCredential => routingCited(app(EmailOtpFactor::class)
            ->enroll(7, ['identifier_id' => routingIdentifierId()])->credentials[0]),
        fn (AuthCredential $c) => app(EmailOtpFactor::class)->revoke($c),
    ],
    'self-service removal' => [
        fn (): AuthCredential => routingCited(
            app(TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example'])->credentials[0]),
        fn (AuthCredential $c) => app(CredentialSelfService::class)
            ->removeFactor(routingSteppedUpSession(), (int) $c->id),
    ],
    'password change' => [
        fn (): AuthCredential => routingCited(AuthCredential::query()
            ->where('user_id', 7)->where('type', 'password')->firstOrFail()),
        fn (AuthCredential $c) => app(CredentialSelfService::class)
            ->changePassword(routingSteppedUpSession(), 'a-new-password'),
    ],
    // The plan's other subject-wide writer, and the one this dataset originally
    // missed: reuse of a disabled password row, writing a new secret.
    'first-credential disabled-row reuse' => [
        function (): AuthCredential {
            $credential = AuthCredential::query()
                ->where('user_id', 7)->where('type', 'password')->firstOrFail();
            app(PasswordFactor::class)->revoke($credential);

            return routingCited($credential);
        },
        fn (AuthCredential $c) => app(\Fissible\Vouch\Enrollment\FirstCredentialEnrollment::class)->enroll(
            new \Fissible\Vouch\Enrollment\FirstCredentialRequest(
                userId: 7,
                identifierType: 'email',
                identifierValue: 'ada-again@acme.example',
                password: 'a-replacement-password',
                tenantId: null,
                clientIp: '203.0.113.10',
            ),
        ),
    ],
]);

it('rolls the credential write back when invalidation fails', function (Closure $arrange, Closure $mutate): void {
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    routingIssuer();

    $credential = $arrange();
    $before = routingCredentialState();

    /*
     * Remove the mapping table the invalidation must write, so the facade
     * throws INSIDE its own transaction. TokenAssuranceRecord is final and
     * cannot be doubled; this fails at the same place for the same reason and
     * needs no production seam. DatabaseMigrations restores the schema.
     */
    Schema::drop('auth_token_credentials');

    try {
        $mutate($credential);
    } catch (Throwable) {
        // Surfacing or swallowing the failure is the writer's design choice.
        // What must hold is the state afterwards.
    }

    /*
     * The WHOLE credential table, not just this row's disabled_at. A password
     * replace that rewrote the secret before calling the facade, or that left
     * its newly created replacement row behind, restores disabled_at and would
     * otherwise pass while having been visibly non-atomic.
     *
     * What this probe proves, stated so it is not over-trusted: the
     * straightforward non-atomic implementation — write first, call the facade,
     * let its failure escape — fails here. It cannot exclude an adversarial
     * implementation that pre-writes on another transaction and compensates
     * after the failure. Catching that would need instrumentation this suite
     * does not have — connection-level tracing, or a database trigger auditing
     * writes to auth_credentials.
     * And it is not evidence the mutation works AT ALL: a path that refused
     * before reaching invalidation also leaves the table untouched. That half
     * is covered by the per-writer tests above, each of which asserts the
     * credential really changed on the success path.
     */
    expect(routingCredentialState())->toBe($before);
})->with('revoking writers');


/* ---- the facade must share the writer's connection ---------------------- */

it('keeps the credential write and the invalidation on one connection', function (): void {
    /*
     * FirstCredentialEnrollment takes an injected Connection — the contention
     * suite constructs it on a named one — but resolved CredentialMutation from
     * the container, which is bound to the DEFAULT connection. The credential
     * write then happened on the caller's connection while the locks and the
     * assurance invalidation happened on another.
     *
     * That is not a slow path or a style problem: the two halves are in
     * different transactions on different connections, so they cannot roll back
     * together. Rolling the caller's connection back undoes the credential
     * change and leaves the invalidation committed — a subject whose password
     * did not change, with its tokens revoked — and the mirror case loses the
     * revocation instead.
     *
     * Proven by rolling back and requiring BOTH halves to be untouched. On one
     * connection that is automatic; across two it cannot hold.
     */
    routingUser();
    app(PasswordFactor::class)->enroll(7, ['password' => 'old-password']);
    $password = AuthCredential::query()->where('user_id', 7)->where('type', 'password')->firstOrFail();
    app(PasswordFactor::class)->revoke($password);
    $secretBefore = stringValue(AuthCredential::query()->findOrFail($password->id)->secret);

    routingToken('cites-the-reused-row', [stringValue($password->id)]);
    routingIssuer();

    Config::set('database.connections.enrolling', Config::array(
        'database.connections.' . Config::string('database.default'),
    ));
    $connection = DB::connection('enrolling');

    $connection->beginTransaction();

    try {
        app()->makeWith(\Fissible\Vouch\Enrollment\FirstCredentialEnrollment::class, [
            'connection' => $connection,
        ])->enroll(new \Fissible\Vouch\Enrollment\FirstCredentialRequest(
            userId: 7,
            identifierType: 'email',
            identifierValue: 'ada-again@acme.example',
            password: 'a-replacement-password',
            tenantId: null,
            clientIp: '203.0.113.10',
        ));
    } finally {
        $connection->rollBack();
    }

    // Both halves rolled back together, or neither is trustworthy.
    expect(stringValue(AuthCredential::query()->findOrFail($password->id)->secret))->toBe($secretBefore)
        ->and(AuthCredential::query()->whereKey($password->id)->whereNotNull('disabled_at')->exists())->toBeTrue()
        ->and(routingSurvivors())->toBe(['cites-the-reused-row']);
});
