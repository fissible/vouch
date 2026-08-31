<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Http;

use DateTimeImmutable;
use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerCollision;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Http\Request;
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
    public function an_unauthenticated_request_is_not_the_gates_business(): void
    {
        /*
         * No principal at all is the host's authentication layer to refuse, not
         * this gate's. Answering it here would make Vouch the reason an
         * anonymous request failed, and would answer with a token challenge to
         * a caller holding no token.
         */
        $this->getJson('/gated')->assertStatus(401);

        // Whatever refused it, it was not a Vouch step-up challenge.
        $header = (string) $this->getJson('/gated')->headers->get('WWW-Authenticate');
        self::assertStringNotContainsString('insufficient_user_authentication', $header);
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
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([]));

        $this->withToken('some-other-schemes-token')->getJson('/gated')->assertOk();
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
        $this->withToken(TokenUser::query()->findOrFail(7)->createToken('x')->plainTextToken)
            ->getJson('/bare-gated')->assertStatus(401);
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
            $this->withToken($direct)->getJson($uri)->assertStatus(401);
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
        $this->withToken(TokenUser::query()->findOrFail(7)->createToken('y')->plainTextToken)
            ->getJson('/no-auth-middleware')->assertStatus(401);
    }
}
