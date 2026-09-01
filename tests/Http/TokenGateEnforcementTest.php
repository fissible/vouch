<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Http;

use DateTimeImmutable;
use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Http\AssertsTokenGateResponses;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerCollision;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 4 — WHEN the gate applies, which is as important as what it renders.
 *
 * Default-deny is only safe if it is scoped precisely. A gate that also caught
 * cookie-authenticated SPA traffic would break every browser session in the
 * host application on the day it was installed; one that missed a directly
 * minted Sanctum token would be decorative.
 *
 * §2 settles the rule: the gate applies if and only if the request is
 * TOKEN-authenticated, decided by asking registered issuers rather than by
 * reading the Authorization header — because Sanctum may select a cookie actor
 * on a request that carries a bearer header, and believing the header would
 * claim a request Sanctum never authenticated that way.
 */
final class TokenGateEnforcementTest extends TestCase
{
    use AssertsTokenGateResponses;
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', TokenUser::class);

        /*
         * ARMED EXPLICITLY. The gate ships in observe mode, because installing
         * it armed would invalidate every pre-existing Sanctum token in a host
         * application the moment the package booted (see TokenGateModeTest).
         * Every assertion in this file is about the ARMED behaviour, so it says
         * so — otherwise these tests would pass vacuously against a gate that
         * refuses nothing.
         */
        $app['config']->set('vouch.token_gate.mode', 'enforce');
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createTokenSubjectTables();
        TokenUser::query()->create(['id' => 7, 'name' => 'ada']);

        Route::middleware(['api', 'vouch.token:aal1'])->get('/gated', fn (): string => 'reached');
    }

    private function subject(int $id = 7): SubjectKey
    {
        return SubjectKey::of((new TokenUser)->getMorphClass(), $id);
    }

    private function recordedToken(): string
    {
        $user = TokenUser::query()->findOrFail(7);
        $new = $user->createToken('api');

        app(TokenAssuranceRecord::class)->store(
            'sanctum', stringValue($new->accessToken->getKey()), $this->subject(), null, ActorKind::Human,
            [new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))],
        );

        return $new->plainTextToken;
    }

    #[Test]
    public function a_cookie_authenticated_request_passes_through_untouched(): void
    {
        /*
         * THE compatibility gate. Sanctum's stateful guard authenticates an SPA
         * from a session cookie and attaches a TransientToken — not a personal
         * access token — so no issuer claims the request and the gate must not
         * apply. Getting this wrong breaks every browser session the day the
         * package is installed, which is the loudest possible regression and
         * the easiest to cause by reading a header.
         */
        $this->actingAs(TokenUser::query()->findOrFail(7), 'sanctum')
            ->getJson('/gated')
            ->assertOk()
            ->assertSee('reached');
    }

    #[Test]
    public function an_unauthenticated_request_passes_through_rather_than_being_gated(): void
    {
        /*
         * No issuer claims an anonymous request, so §2 requires the gate to
         * pass it through and let the host's auth middleware decide. This route
         * deliberately carries no auth:sanctum, so a pass-through reaches the
         * controller.
         *
         * An earlier draft asserted a 401 here — which the framework produces on
         * a route that HAS auth middleware, so it tested Laravel rather than
         * Vouch, and would have passed against a gate that rejected everything.
         */
        $this->getJson('/gated')->assertOk()->assertSee('reached');
    }

    #[Test]
    public function a_bearer_header_does_not_claim_a_request_sanctum_authenticated_by_cookie(): void
    {
        /*
         * §2's precedence row, and the reason the gate asks the issuer rather
         * than reading the header. Sanctum's guard tries stateful guards FIRST,
         * so a request carrying BOTH a session cookie and a bearer header is
         * authenticated as the cookie actor with a TransientToken attached.
         *
         * A gate reading the Authorization header would see a bearer, decide the
         * request is token-authenticated, and demand an assurance record for a
         * token Sanctum never used.
         */
        $this->actingAs(TokenUser::query()->findOrFail(7), 'sanctum')
            ->withToken('a-bearer-that-was-not-used')
            ->getJson('/gated')
            ->assertOk()
            ->assertSee('reached');
    }

    #[Test]
    public function a_token_no_registered_issuer_claims_passes_through(): void
    {
        /*
         * A Passport or JWT bearer belongs to a mechanism Vouch does not model.
         * Refusing it would make installing Vouch break every other token
         * scheme in the application; §2 is explicit that only claimed tokens
         * are gated.
         */
        /*
         * Sanctum stays REGISTERED. An earlier draft emptied the registry, which
         * made the test vacuous: with no issuers at all it cannot catch a gate
         * that sniffs the Authorization header, nor a Sanctum resolver that
         * wrongly claims a foreign bearer. The string below is simply one
         * Sanctum does not recognise.
         */
        $this->withToken('passport|or|jwt|not|sanctums')->getJson('/gated')->assertOk()->assertSee('reached');
    }

    #[Test]
    public function two_issuers_claiming_one_request_is_a_loud_configuration_error(): void
    {
        /*
         * Not a 401. If two drivers both claim a request, the deployment is
         * misconfigured and Vouch cannot know whose assurance record applies —
         * answering with an authentication failure would hide a configuration
         * bug behind a plausible-looking rejection, and the host would chase
         * the wrong thing.
         */
        $claimer = fn (string $key): TokenIssuer => new class($key, $this->subject()) implements TokenIssuer {
            public function __construct(private string $key, private SubjectKey $subject) {}

            public function issuerKey(): string
            {
                return $this->key;
            }

            public function supportsTransactionalIssuance(): bool
            {
                return true;
            }

            public function issue(\Illuminate\Database\ConnectionInterface $connection, \Fissible\Vouch\Tokens\TokenGrant $grant): \Fissible\Vouch\Tokens\IssuedToken
            {
                throw new \RuntimeException('not used');
            }

            // Narrowed from ?ResolvedToken deliberately: this fake ALWAYS claims,
            // which is the whole point — two of them collide on one request.
            public function resolveForRequest(Request $request): ResolvedToken
            {
                return new ResolvedToken($this->key, '1', $this->subject, true);
            }

            public function revoke(string $tokenKey): void {}
        };

        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([$claimer('a'), $claimer('b')]));

        $this->expectException(TokenIssuerCollision::class);

        $this->withoutExceptionHandling()->withToken('claimed-twice')->getJson('/gated');
    }

    #[Test]
    public function the_gate_applies_wherever_the_host_wires_it(): void
    {
        /*
         * The alias is the whole surface: a host names it on any route or group
         * it chooses. Asserting it works on a custom group as well as `api`
         * keeps the gate from silently depending on one group's ordering.
         */
        Route::middleware(['vouch.token:aal1'])->get('/bare-gated', fn (): string => 'reached');

        $this->withToken($this->recordedToken())->getJson('/bare-gated')->assertOk();

        self::assertSame($this->canonicalRejection(), $this->responseTuple(
            $this->withToken(TokenUser::query()->findOrFail(7)->createToken('x')->plainTextToken)
                ->getJson('/bare-gated'),
        ));
    }

    #[Test]
    public function a_directly_minted_token_is_rejected_on_every_boundary(): void
    {
        /*
         * THE GATE for this task, stated as the plan states it: a token minted
         * straight through Sanctum, bypassing Vouch::issueToken, has no
         * assurance record and must be refused everywhere the gate is wired —
         * not merely on the first route someone remembered to protect.
         */
        Route::middleware(['api', 'vouch.token:aal1'])->get('/gated-two', fn (): string => 'reached');
        Route::middleware(['api', 'vouch.token:aal2'])->get('/gated-three', fn (): string => 'reached');

        $direct = TokenUser::query()->findOrFail(7)->createToken('direct')->plainTextToken;

        foreach (['/gated', '/gated-two', '/gated-three'] as $uri) {
            self::assertSame(
                $this->canonicalRejection(),
                $this->responseTuple($this->withToken($direct)->getJson($uri)),
                "boundary: {$uri}",
            );
        }
    }

    #[Test]
    public function the_gate_does_not_require_auth_sanctum_to_have_run_first(): void
    {
        /*
         * The middleware must resolve the token itself rather than assuming an
         * earlier auth middleware populated the request. A host that wires
         * vouch.token without auth:sanctum, or orders them differently, still
         * gets the gate — otherwise enforcement depends on middleware order,
         * which is exactly the kind of silent hole default-deny is for.
         */
        Route::middleware(['vouch.token:aal1'])->get('/no-auth-middleware', fn (): string => 'reached');

        $this->withToken($this->recordedToken())->getJson('/no-auth-middleware')->assertOk();

        self::assertSame($this->canonicalRejection(), $this->responseTuple(
            $this->withToken(TokenUser::query()->findOrFail(7)->createToken('y')->plainTextToken)
                ->getJson('/no-auth-middleware'),
        ));
    }

    #[Test]
    public function a_valid_vouch_issued_token_passes_the_gate(): void
    {
        /*
         * The end-to-end path, which nothing else here covers: a token minted
         * through Vouch::issueToken carries an assurance record by construction,
         * so the gate that rejects directly-minted tokens must admit this one.
         * Without it, a gate that rejected EVERYTHING would satisfy every other
         * rejection test in this file.
         */
        \Fissible\Vouch\Models\AuthPolicy::query()->create([
            'tenant_id' => null, 'scope' => 'token_issue',
            'document' => ['all_of' => ['password']], 'posture' => 'friendly',
        ]);

        app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
        $credential = \Fissible\Vouch\Models\AuthCredential::query()->where('user_id', 7)->firstOrFail();

        $this->actingAs(TokenUser::query()->findOrFail(7));
        session()->start();

        $factors = [new SatisfiedFactor('password', stringValue($credential->id), FactorKind::Knowledge,
            FactorStrength::Knowledge, false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))];

        app(\Fissible\Vouch\Sessions\SessionLifecycle::class)->establish(
            new \Fissible\Vouch\Flow\AuthSuccess(7, $factors,
                \Fissible\Vouch\Kernel\Assurance\AssuranceFacts::fromFactors($factors), 'ignored', 'ignored', null),
        );

        $issued = \Illuminate\Support\Facades\DB::transaction(
            fn () => \Fissible\Vouch\Vouch::issueToken(
                new \Fissible\Vouch\Tokens\TokenGrant($this->subject(), 'api', ['orders:read']),
            ),
        );

        $this->withToken($issued->plainText)->getJson('/gated')->assertOk()->assertSee('reached');
    }

    /*
     * Tenant mismatch moved to TokenGateResponseTest, where it asserts the
     * complete canonical tuple. Here it only checked a 401, which would have
     * admitted a challenge, a body, or missing cache controls.
     */

    #[Test]
    public function resolving_a_request_never_reselects_the_application_guard(): void
    {
        /*
         * Measured, not assumed: with a resolver that called
         * auth()->shouldUse('sanctum'), a bare request carrying no bearer
         * token at all moved the default driver from web to sanctum,
         * after which Auth::logout() and Auth::attempt() both threw
         * BadMethodCallException on RequestGuard. The gate ships in the web
         * group, so that would have broken session login and logout in every
         * Sanctum-installed host on the day Vouch was installed.
         *
         * Asking who a request is must not decide who the application asks.
         */
        $before = Auth::getDefaultDriver();

        app(TokenIssuerRegistry::class)->resolveForRequest(Request::create('/dashboard'));

        $this->assertSame($before, Auth::getDefaultDriver());
        $this->assertSame('web', Auth::getDefaultDriver());

        /*
         * The methods a session host actually calls must remain reachable.
         * Asserted as the guard's contract rather than by attempting a
         * credential: RequestGuard is not a StatefulGuard, which is exactly
         * why logout() and attempt() threw. A real Auth::attempt() would also
         * have queried the fixture's user table for an "email" column it does
         * not have — engine-dependent, and incidental to the rule being
         * pinned, which is about which guard is selected, not credentials.
         */
        $this->assertInstanceOf(StatefulGuard::class, Auth::guard());
        Auth::logout();
    }

    #[Test]
    public function resolving_a_token_request_also_leaves_the_application_guard_alone(): void
    {
        /*
         * The companion to the test above, and the one that could regress
         * quietly: it would be tempting to "only" reselect the guard once a
         * token is actually present.
         *
         * Deliberately NO auth:sanctum here. Laravel's own Authenticate
         * middleware calls shouldUse() on success, so on a route the host
         * opted in the sanctum driver is correct and the host chose it. This
         * route is the uncovered case: a request carrying a bearer token that
         * the gate must still evaluate, on a route whose host never asked for
         * the sanctum guard. Evaluating it must not select it either.
         */
        Route::middleware(['api', 'vouch.token:aal1'])->get('/guard-after', function (): array {
            return ['driver' => Auth::getDefaultDriver()];
        });

        $user = TokenUser::query()->findOrFail(7);
        $new = $user->createToken('api');
        app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
            $this->subject(), null, ActorKind::Human,
            [new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))]);

        $this->withToken($new->plainTextToken)->getJson('/guard-after')
            ->assertOk()
            ->assertJson(['driver' => 'web']);
    }

    #[Test]
    public function a_configured_sanctum_guard_whose_driver_is_absent_is_not_a_token_request(): void
    {
        /*
         * The "Sanctum is optional" guard reads config, but config presence
         * is not driver availability: a host can carry a sanctum guard entry
         * whose driver was never registered — a published skeleton, a removed
         * dependency, a renamed driver. Resolving then threw "Auth driver
         * [sanctum] for guard [sanctum] is not defined" and turned every gated
         * request into a 500. Unusable machinery means no token, not an error.
         */
        config(['auth.guards.sanctum' => ['driver' => 'sanctum-not-registered', 'provider' => 'users']]);

        Route::middleware(['api', 'vouch.token:aal1'])->get('/no-driver', fn (): string => 'reached');

        $this->getJson('/no-driver')->assertOk()->assertSee('reached');
    }

    #[Test]
    public function the_gate_leaves_sanctum_abilities_alone(): void
    {
        /*
         * Abilities are the host's authorization and cross the boundary
         * uninterpreted (§3, departure 3). A gate that consumed or reset them
         * would silently widen or narrow every token it admitted.
         */
        /*
         * `auth:sanctum` is on the route because that is how a real host
         * reaches $request->user() from a token. The original fixture omitted
         * it, and the only way to satisfy it was for Vouch to select the
         * sanctum guard application-wide from inside its resolver — which then
         * broke Auth::logout()/attempt() on every cookie request in the web
         * group. Vouch does not do the host's guard selection for it.
         */
        Route::middleware(['api', 'auth:sanctum', 'vouch.token:aal1'])->get('/abilities', function (Request $request): array {
            // The configured user model is TokenUser, which uses HasApiTokens;
            // narrowing to it is what makes currentAccessToken() a real method
            // rather than a hope about the base class.
            $user = $request->user();
            $token = $user instanceof TokenUser ? $user->currentAccessToken() : null;

            return [
                'can' => $token instanceof \Laravel\Sanctum\PersonalAccessToken && $token->can('orders:read'),
                'cannot' => $token instanceof \Laravel\Sanctum\PersonalAccessToken && $token->can('admin'),
            ];
        });

        $user = TokenUser::query()->findOrFail(7);
        $new = $user->createToken('api', ['orders:read']);
        app(TokenAssuranceRecord::class)->store('sanctum', stringValue($new->accessToken->getKey()),
            $this->subject(), null, ActorKind::Human,
            [new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00'))]);

        $this->withToken($new->plainTextToken)->getJson('/abilities')
            ->assertOk()
            ->assertJson(['can' => true, 'cannot' => false]);
    }

    #[Test]
    public function a_malformed_recency_argument_is_a_loud_error(): void
    {
        // A max_age that failed to parse must not degrade to "no recency
        // limit", which would silently unenforce the stricter half of a
        // requirement while the route still looked configured.
        Route::middleware(['api', 'vouch.token:aal1,15 minutes'])->get('/bad-arg', fn (): string => 'reached');

        $this->expectException(\InvalidArgumentException::class);

        $this->withoutExceptionHandling()->withToken($this->recordedToken())->getJson('/bad-arg');
    }

    #[Test]
    #[\PHPUnit\Framework\Attributes\DataProvider('installedGroups')]
    public function the_gate_installs_into_the_host_middleware_groups(string $group): void
    {
        /*
         * NO EXPLICIT ALIAS. Every other route in this file names vouch.token,
         * so none of them can tell whether the gate installs itself into the
         * host's groups — which the plan requires and which is how a host gets
         * default-deny without editing every route.
         *
         * Deliberately mechanism-independent: it asserts observable coverage,
         * not callAfterResolving, not ordering, not which kernel hook is used.
         * An unrecorded real Sanctum token on a plain group route must be
         * refused.
         */
        Route::middleware([$group])->get("/grouped-{$group}", fn (): string => 'reached');

        $direct = TokenUser::query()->findOrFail(7)->createToken('direct')->plainTextToken;

        /*
         * The CANONICAL TUPLE, not a bare 401. An earlier draft of this very
         * test asserted only the status — the same weakness that had just been
         * fixed for tenant mismatch, repeated in the test added to fix it. A
         * status-only assertion admits a step-up challenge, a body, or missing
         * cache controls, none of which the contract allows.
         */
        self::assertSame(
            $this->canonicalRejection(),
            $this->responseTuple($this->withToken($direct)->getJson("/grouped-{$group}")),
        );
    }

    /** @return array<string, array{string}> */
    public static function installedGroups(): array
    {
        return ['web' => ['web'], 'api' => ['api']];
    }
}
