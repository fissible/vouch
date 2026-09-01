<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Sessions\SessionRotationFailed;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\Tests\Support\Tenancy\FixedTenantResolver;
use Fissible\Vouch\Tests\Support\Tenancy\MutableTenantResolver;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\IssuanceRefused;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\Vouch;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4b issue #6 — the tenant the user authenticated under reaches the token.
 *
 * `AuthFlow` stamps the attempt's tenant from `TenantResolver` and uses it for
 * posture, throttle keys and policy selection, then dropped it when building
 * `AuthSuccess`. `SessionLifecycle` wrote a literal `null`, so no session could
 * produce tenant-scoped evidence and tenant-scoped issuance was unreachable.
 *
 * The refusal was correct while the capability was missing. Supplying the
 * capability is most of this issue; the rest is that supplying it makes two
 * mismatches REACHABLE that nothing previously refused, because the record was
 * stored with the GRANT's tenant while the policy was looked up with the
 * EVIDENCE's.
 *
 * The positive case therefore runs through the real flow with real tenant
 * resolution. A hand-built AuthSuccess would prove the writer stores what it is
 * given, which was never in doubt — the defect was upstream of the writer.
 */
final class TenantProvenanceTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @var array<string, mixed> */
    private array $extraFields = [];

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', TokenUser::class);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createTokenSubjectTables();
        TokenUser::query()->create(['id' => 7, 'name' => 'ada']);
        AuthIdentifier::create([
            'user_id' => 7,
            'type' => 'email',
            'value' => 'ada@acme.example',
            'verified_at' => now(),
        ]);
        app(PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    }

    private function subject(): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), '7');
    }

    private function resolveTenantAs(?string $tenantId): void
    {
        app()->bind(TenantResolver::class, fn (): TenantResolver => new FixedTenantResolver($tenantId));
    }

    /** Policies are per tenant; issuance looks one up for the evidence's tenant. */
    private function policiesFor(?string ...$tenants): void
    {
        foreach ($tenants as $tenant) {
            // 'login' is the scope AuthFlow evaluates; 'token_issue' is
            // issuance's. Both are per tenant, which is the point.
            foreach (['login', 'token_issue'] as $scope) {
                AuthPolicy::query()->create([
                    'tenant_id' => $tenant,
                    'scope' => $scope,
                    'document' => ['all_of' => ['password']],
                    'posture' => 'friendly',
                ]);
            }
        }
    }

    /**
     * Authenticate through the REAL flow, so the tenant travels the path this
     * issue is about rather than being handed to the writer.
     */
    private function authenticate(): void
    {
        session()->start();

        $binding = str_repeat('t', 64);
        // Including 'begin': tenant resolution happens THERE, so omitting it
        // would leave the only step that reads the tenant untested.
        $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', $this->extraFields, $binding));
        $handle = stringValue($begun->handle);

        app(AuthFlow::class)->advance(new FlowRequest(
            $handle, 'submit', ['identifier' => 'ada@acme.example'] + $this->extraFields, $binding,
        ));
        $result = app(AuthFlow::class)->advance(new FlowRequest(
            $handle, 'submit', ['password' => 'correct horse battery staple'] + $this->extraFields, $binding,
        ));

        /*
         * Completed through FlowResultHandler, the package's own completion
         * point, rather than by calling SessionLifecycle directly. That is what
         * makes this the REAL path: the tenant has to survive
         * AuthFlow -> AuthSuccess -> the handler -> the session writer, and the
         * defect was the second arrow. It also logs into the host guard, which
         * issuance resolves its session from.
         */
        $this->handler()->handle($result);
    }

    private function handler(): \Fissible\Vouch\Http\FlowResultHandler
    {
        return new \Fissible\Vouch\Http\FlowResultHandler(
            app(\Fissible\Vouch\Sessions\SessionLifecycle::class),
            app(\Fissible\Vouch\Recovery\GraceGuard::class),
            // Constructed rather than resolved: the handler needs a
            // StatefulGuard, which the test container does not bind.
            auth()->guard('web'),
            session()->driver(),
            app(\Fissible\Vouch\Sessions\SessionRebinder::class),
        );
    }

    /** @param array<string, mixed> $extra Additional fields on every submission. */
    private function authenticateSubmitting(array $extra): void
    {
        $this->extraFields = $extra;

        try {
            $this->authenticate();
        } finally {
            $this->extraFields = [];
        }
    }

    private function issue(?string $grantTenant): void
    {
        DB::transaction(fn () => Vouch::issueToken(
            new TokenGrant($this->subject(), 'api', ['orders:read'], $grantTenant),
        ));
    }

    /**
     * Assert issuance refuses BECAUSE OF THE TENANT, not for some earlier reason.
     *
     * Without this, every mismatch test passes while the session is simply
     * unfindable (#21) — the refusal arrives before the tenant is ever compared,
     * and the test cannot tell the two apart. So the session binding is proven
     * to resolve first, the message is required to be the tenant branch, and no
     * record may be written.
     */
    private function assertRefusedOnTenant(?string $grantTenant): void
    {
        self::assertSame(
            SessionBinding::for(session()->getId(), BindingDomain::Session),
            stringValue(AuthSession::query()->firstOrFail()->session_binding),
            'The session must resolve, or the refusal below proves nothing about tenants.',
        );

        try {
            $this->issue($grantTenant);
            self::fail('Issuance should refuse a tenant mismatch.');
        } catch (IssuanceRefused $refused) {
            // The exact branch, not merely a message mentioning tenants: an
            // unrelated refusal could satisfy a substring match.
            self::assertSame(
                'The token grant tenant does not match the authenticated session.',
                $refused->getMessage(),
            );
        }

        /*
         * And nothing was minted. Zero assurance rows alone would permit
         * "issue the token, then throw before recording it" — which leaves a
         * live bearer with no record, the worst of both outcomes.
         */
        self::assertSame(0, DB::table('auth_token_assurances')->count());
        self::assertSame(0, DB::table('personal_access_tokens')->count());
    }

    #[Test]
    public function auth_success_requires_an_explicit_tenant(): void
    {
        /*
         * The clause no behavioural test can reach, because a defaulted
         * parameter behaves identically at every call site that passes one.
         *
         * The entire defect this issue closes is a tenant being dropped by
         * omission. A parameter that CAN be omitted invites exactly that again,
         * and the next construction site to forget it gets global scope
         * silently — which is the bug, not a safe default.
         */
        $parameters = (new \ReflectionClass(\Fissible\Vouch\Flow\AuthSuccess::class))
            ->getConstructor()?->getParameters() ?? [];

        $tenant = null;
        foreach ($parameters as $parameter) {
            if ($parameter->getName() === 'tenantId') {
                $tenant = $parameter;
            }
        }

        self::assertNotNull($tenant, 'AuthSuccess must carry the tenant it authenticated under.');
        self::assertFalse(
            $tenant->isDefaultValueAvailable(),
            'AuthSuccess::$tenantId must be required, so every construction site states it.',
        );

        /*
         * `?string` exactly. "allows null" would also accept `mixed`, which is
         * required and nullable and states nothing — a weaker contract that
         * passes the same assertion.
         */
        self::assertSame('?string', (string) $tenant->getType());
    }

    #[Test]
    public function the_session_written_by_a_login_is_findable_afterwards(): void
    {
        /*
         * Issue #21, found because this file's positive case is required to run
         * through the real flow rather than a hand-built AuthSuccess.
         *
         * FlowResultHandler::establish() writes the binding and then calls
         * loginUsingId(), which migrates the session id — measured, not
         * inferred — so the row is bound to an id that no longer exists the
         * moment login completes. Nothing rebinds it, and every session lookup
         * in the package goes through SessionBinding::for(current id).
         *
         * The user is left with a session row nothing can find: no Vouch
         * session on assurance-gated routes, and issuance refusing with "Token
         * issuance requires the authenticated host session".
         *
         * It is untested because every other fixture establishes the session
         * directly, where nothing migrates afterwards — so the binding matches
         * by construction. This spans the seam that fixture skips, and #6
         * cannot be demonstrated end to end until it holds.
         */
        $this->resolveTenantAs(null);
        $this->policiesFor(null);

        $this->authenticate();

        $binding = SessionBinding::for(session()->getId(), BindingDomain::Session);

        self::assertSame(
            $binding,
            stringValue(AuthSession::query()->firstOrFail()->session_binding),
            'The session written by the login is bound to an id that no longer exists.',
        );
    }

    #[Test]
    public function a_tenant_login_produces_tenant_scoped_session_evidence(): void
    {
        /*
         * The wiring, asserted where it broke. The flow already knew 'acme' —
         * it chose the posture and the throttle keys with it — and the session
         * writer received null.
         */
        $this->resolveTenantAs('acme');
        $this->policiesFor('acme');

        $this->authenticate();

        $session = AuthSession::query()->firstOrFail();
        $evidence = SessionEvidence::for($session);

        self::assertInstanceOf(AssuranceEvidence::class, $evidence);
        self::assertSame('acme', $evidence->tenantId);
    }

    #[Test]
    public function a_global_login_still_produces_global_evidence(): void
    {
        /*
         * The other half of the same wiring. A null resolver must keep meaning
         * global, not become an empty string or a missing key — the proof is
         * compared with strict equality downstream.
         */
        $this->resolveTenantAs(null);
        $this->policiesFor(null);

        $this->authenticate();

        $evidence = SessionEvidence::for(AuthSession::query()->firstOrFail());

        self::assertInstanceOf(AssuranceEvidence::class, $evidence);
        self::assertNull($evidence->tenantId);
    }

    #[Test]
    public function tenant_scoped_issuance_succeeds_when_the_login_carried_that_tenant(): void
    {
        /*
         * The capability this issue delivers. TokenIssuanceTest recorded its
         * absence as a deliberate refusal; that refusal is now wrong and this
         * is what replaces it.
         */
        $this->resolveTenantAs('acme');
        $this->policiesFor('acme');
        $this->authenticate();

        $this->issue('acme');

        self::assertSame('acme', DB::table('auth_token_assurances')->value('tenant_id'));
    }

    #[Test]
    public function global_issuance_still_succeeds_from_a_global_login(): void
    {
        $this->resolveTenantAs(null);
        $this->policiesFor(null);
        $this->authenticate();

        $this->issue(null);

        self::assertNull(DB::table('auth_token_assurances')->value('tenant_id'));
        self::assertSame(1, DB::table('auth_token_assurances')->count());
    }

    #[Test]
    public function a_grant_for_another_tenant_is_refused(): void
    {
        /*
         * Newly REACHABLE, and the reason this issue is not pure wiring. The
         * record was stored with the GRANT's tenant while the policy was looked
         * up with the EVIDENCE's, so an acme session could mint a token scoped
         * to a tenant whose policy never governed the login — and nothing
         * refused it, because the old check only asked whether the evidence
         * tenant was null.
         */
        $this->resolveTenantAs('acme');
        $this->policiesFor('acme', 'other');
        $this->authenticate();

        $this->assertRefusedOnTenant('other');
    }

    #[Test]
    public function a_global_grant_from_a_tenant_login_is_refused(): void
    {
        /*
         * The direction easiest to wave through, because "global" sounds like
         * less. It is not less: EvidenceComparator matches tenants with strict
         * equality, so a global token is the one usable where the resolver
         * returns null — typically the administrative surface — and a tenant
         * login's policy never governed that.
         */
        $this->resolveTenantAs('acme');
        $this->policiesFor('acme', null);
        $this->authenticate();

        $this->assertRefusedOnTenant(null);
    }

    #[Test]
    public function a_tenant_grant_from_a_global_login_is_still_refused(): void
    {
        /*
         * The only mismatch reachable before this issue, and it must survive
         * the rewrite. The old asymmetric check is removed because equality
         * subsumes it; this proves the removal lost nothing.
         */
        $this->resolveTenantAs(null);
        $this->policiesFor(null, 'acme');
        $this->authenticate();

        $this->assertRefusedOnTenant('acme');
    }

    #[Test]
    public function the_policy_and_the_record_use_the_same_verified_tenant(): void
    {
        /*
         * The structural cause of the mismatch, pinned so a future refactor
         * cannot reintroduce it by taking the tenant from two places again: the
         * policy that authorised the issuance and the record written for it
         * must describe the same scope.
         */
        $this->resolveTenantAs('acme');

        /*
         * The GLOBAL token_issue policy demands a factor this login never
         * satisfied, so it can only succeed if the acme policy was selected.
         * With identical policies the test could not tell which one authorised
         * the issuance, and an implementation that looked one up by the wrong
         * tenant would pass while storing 'acme' in both places.
         */
        AuthPolicy::query()->create([
            'tenant_id' => null, 'scope' => 'token_issue',
            'document' => ['all_of' => ['password', 'totp']], 'posture' => 'friendly',
        ]);
        $this->policiesFor('acme');
        $this->authenticate();

        $this->issue('acme');

        $record = DB::table('auth_token_assurances')->firstOrFail();
        $proof = json_decode(stringValue($record->assurance_proof), true, 512, JSON_THROW_ON_ERROR);

        self::assertIsArray($proof);
        self::assertSame('acme', $record->tenant_id);
        self::assertSame('acme', $proof['tenant_id'] ?? null);
    }

    #[Test]
    public function a_record_whose_proof_tenant_contradicts_its_column_is_refused(): void
    {
        /*
         * Defense in depth against a state the package cannot produce: the
         * column and the proof are written together in one statement. They can
         * only disagree through corruption or an out-of-band write, and
         * silently believing either one would make the disagreement invisible
         * to the gate — which is exactly the place a tenant confusion would pay
         * off.
         */
        app(TokenAssuranceRecord::class)->store(
            'sanctum', 'tok-1', $this->subject(), 'acme', ActorKind::Human,
            [new SatisfiedFactor('password', '101', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))],
        );

        // Contradict the column only; the serialized proof still says 'acme'.
        DB::table('auth_token_assurances')->where('token_key', 'tok-1')->update(['tenant_id' => 'other']);

        $read = app(TokenAssuranceRecord::class)->read(
            new \Fissible\Vouch\Tokens\ResolvedToken('sanctum', 'tok-1', $this->subject(), usable: true),
        );

        self::assertNull($read->evidence);
        self::assertSame(AssuranceReason::ProofMalformed, $read->reason);
    }

    #[Test]
    public function the_tenant_is_carried_from_the_attempt_not_re_derived_later(): void
    {
        /*
         * The distinction the whole issue rests on, and the one a fixed
         * resolver cannot make. An implementation that asked TenantResolver
         * again when writing the session would agree with one that carried the
         * attempt's tenant in every other test here — both would see 'acme'.
         *
         * So the resolver CHANGES after the attempt is stamped. The evidence
         * must still say 'acme', because that is the scope the user was
         * actually authenticated and policy-evaluated under. Re-deriving would
         * record 'drifted', binding the session to a scope no policy in this
         * login ever consulted.
         */
        $resolver = new MutableTenantResolver('acme');
        app()->instance(TenantResolver::class, $resolver);
        $this->policiesFor('acme', 'drifted');

        session()->start();
        $binding = str_repeat('t', 64);
        $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], $binding));
        $handle = stringValue($begun->handle);
        app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], $binding));

        // The request that stamped the attempt is over; the context moves on.
        $resolver->tenantId = 'drifted';

        $result = app(AuthFlow::class)->advance(
            new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], $binding),
        );
        $this->handler()->handle($result);

        $evidence = SessionEvidence::for(AuthSession::query()->firstOrFail());

        self::assertInstanceOf(AssuranceEvidence::class, $evidence);
        self::assertSame('acme', $evidence->tenantId);
    }

    #[Test]
    public function the_resolver_decides_the_tenant_not_the_request(): void
    {
        /*
         * The tenant is trusted server-side context. A request that names a
         * different one must not influence the evidence — otherwise a caller
         * chooses the scope its own login is evaluated under, which is the
         * whole authority the tenant represents.
         */
        $this->resolveTenantAs('acme');
        $this->policiesFor('acme', 'attacker');

        $this->authenticateSubmitting(['tenant' => 'attacker', 'tenant_id' => 'attacker']);

        $evidence = SessionEvidence::for(AuthSession::query()->firstOrFail());

        self::assertInstanceOf(AssuranceEvidence::class, $evidence);
        self::assertSame('acme', $evidence->tenantId);
    }

    #[Test]
    public function an_empty_string_tenant_is_refused_rather_than_treated_as_global(): void
    {
        /*
         * '' is neither a tenant nor global. Coercing it either way would make
         * a misconfigured resolver silently produce evidence for the wrong
         * scope, and strict equality downstream would then compare against it.
         */
        $this->resolveTenantAs('');
        $this->policiesFor(null, '');

        /*
         * SessionRotationFailed, not MalformedEvidence: SessionLifecycle
         * already catches the evidence error and rethrows as a rotation
         * failure. Demanding the inner type would require a new validation
         * seam rather than the fail-closed behaviour that already exists.
         */
        try {
            $this->authenticate();
            self::fail('An empty-string tenant should not produce a session.');
        } catch (SessionRotationFailed) {
            // The contract is the outcome below.
        }

        self::assertSame(0, AuthSession::query()->count());
    }
}
