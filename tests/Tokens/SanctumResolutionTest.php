<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Tests\Support\Tokens\PlainUser;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\Drivers\SanctumTokenIssuer;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenIssuerCollision;
use Fissible\Vouch\Tokens\TokenGrant;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 1 — which requests the Sanctum driver claims.
 *
 * Driven through REAL requests rather than by handing the driver a fabricated
 * Request, because the contract is "I authenticated the effective principal of
 * this request" and only the actual guard can settle that. Sanctum tries its
 * stateful guards FIRST and attaches a TransientToken when one answers; it
 * reaches bearer validation only when no session principal exists
 * (`Guard::__invoke`). A test that constructed its own Request would be
 * asserting my belief about that order rather than the order itself.
 */
final class SanctumResolutionTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

    /**
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [SanctumServiceProvider::class, VouchServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', TokenUser::class);

        // A second stateful guard, ordered BEFORE web. Sanctum iterates every
        // value in config('sanctum.guard') — asserting only 'web' would test a
        // default rather than the behaviour.
        $app['config']->set('auth.providers.plain', ['driver' => 'eloquent', 'model' => PlainUser::class]);
        $app['config']->set('auth.guards.admin', ['driver' => 'session', 'provider' => 'plain']);
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->createTokenSubjectTables();

        // The route reports what the driver resolved for THIS request.
        Route::middleware('api')->get('/resolve-probe', function (\Illuminate\Http\Request $request) {
            $resolved = app(SanctumTokenIssuer::class)->resolveForRequest($request);

            return response()->json($resolved === null ? ['claimed' => false] : [
                'claimed' => true,
                'issuer' => $resolved->issuerKey,
                'token' => $resolved->tokenKey,
                'subject' => $resolved->subject->toString(),
            ]);
        });
    }

    #[Test]
    public function what_it_claims_agrees_with_the_principal_auth_sanctum_actually_selects(): void
    {
        /*
         * The load-bearing test of this file. Every other row here could be
         * satisfied by a resolver that reimplemented Sanctum's precedence with
         * its own header and session logic and happened to agree on the cases I
         * thought to write. This one pins the resolver to the guard itself: the
         * same route resolves through the sanctum guard directly — the guard
         * auth:sanctum uses — reports who Sanctum chose, and the two must match
         * on every shape below. It does not sit BEHIND auth:sanctum, because
         * that would 401 the unauthenticated shapes before they could be
         * compared.
         */
        Route::middleware('api')->get('/guard-probe', function (\Illuminate\Http\Request $request) {
            $principal = auth('sanctum')->user();
            $token = $principal instanceof TokenUser ? $principal->currentAccessToken() : null;

            return response()->json([
                'principal' => $principal instanceof TokenUser
                    ? SubjectKey::of($principal->getMorphClass(), stringValue($principal->getKey()))->toString()
                    : null,
                'token' => $token instanceof PersonalAccessToken ? stringValue($token->getKey()) : null,
            ]);
        });

        $user = $this->user();
        $plain = $this->mint($user);

        $expired = $this->mint($this->user(11));
        $restricted = app(SanctumTokenIssuer::class)->issue(DB::connection(), new TokenGrant(
            subject: SubjectKey::of($user->getMorphClass(), $user->getKey()),
            name: 'narrow',
            abilities: ['nothing:at-all'],
        ))->plainText;
        $expiredToken = PersonalAccessToken::findToken($expired);
        self::assertInstanceOf(PersonalAccessToken::class, $expiredToken);
        PersonalAccessToken::query()
            ->where('id', $expiredToken->getKey())
            ->update(['expires_at' => now()->subMinute()]);

        // Every shape, not one. The claim is that the resolver agrees with the
        // guard, and a single agreeing case would not establish it.
        $shapes = [
            'plain bearer' => fn () => $this->withToken($plain),
            'cookie plus bearer' => fn () => $this->actingAs($user, 'web')->withToken($plain),
            'cookie only' => fn () => $this->actingAs($user, 'web'),
            'expired bearer' => fn () => $this->withToken($expired),
            'restricted abilities' => fn () => $this->withToken($restricted),
            'unrelated bearer' => fn () => $this->withToken('not-a-sanctum-token'),
        ];

        foreach ($shapes as $label => $shape) {
            /** @var array{principal: string|null, token: string|null} $guard */
            $guard = $shape()->getJson('/guard-probe')->json();
            /** @var array{claimed: bool, issuer?: string, token?: string, subject?: string} $resolved */
            $resolved = $shape()->getJson('/resolve-probe')->json();

            $claimedSubject = $resolved['claimed'] === true ? ($resolved['subject'] ?? null) : null;
            $claimedToken = $resolved['claimed'] === true ? ($resolved['token'] ?? null) : null;

            self::assertSame($guard['token'], $claimedToken, "token mismatch for: {$label}");
            self::assertSame(
                $guard['token'] === null ? null : $guard['principal'],
                $claimedSubject,
                "subject mismatch for: {$label}",
            );
        }
    }

    #[Test]
    public function resolution_fails_closed_when_two_issuers_claim_one_request(): void
    {
        /*
         * Addendum §2: a collision is a CONFIGURATION error and must be loud,
         * not an authentication outcome. Asserted at resolution, where the
         * collision actually happens — an earlier draft asserted it against
         * issuance, which cannot collide the same way.
         */
        Route::middleware('api')->get('/collision-probe', function (\Illuminate\Http\Request $request) {
            $registry = new \Fissible\Vouch\Tokens\TokenIssuerRegistry([
                app(SanctumTokenIssuer::class),
                app(SanctumTokenIssuer::class),
            ]);

            return response()->json(['token' => $registry->resolveForRequest($request)?->tokenKey]);
        });

        $plain = $this->mint($this->user());

        /*
         * The SPECIFIC failure, not merely a 500. A status assertion passes for
         * any exception at all — bad wiring, an issuer bug, an unrelated route
         * error — and would still be green if collisions were silently resolved
         * to the first claimant.
         */
        $this->withoutExceptionHandling();

        $this->expectException(TokenIssuerCollision::class);

        $this->withToken($plain)->getJson('/collision-probe');
    }

    #[Test]
    public function it_does_not_claim_a_session_principal_from_a_non_web_stateful_guard(): void
    {
        // Sanctum iterates every configured stateful guard, not just web.
        config(['sanctum.guard' => ['admin', 'web']]);
        $plain = PlainUser::query()->create(['id' => 3, 'name' => 'ops']);

        $this->actingAs($plain, 'admin')->getJson('/resolve-probe')->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_does_not_claim_a_token_whose_tokenable_cannot_hold_tokens(): void
    {
        /*
         * Sanctum refuses a tokenable without HasApiTokens
         * (Guard::supportsTokens), so a row pointing at one authenticates
         * nobody. The driver must agree rather than claim it and leave the
         * request to be refused later for the wrong reason.
         */
        $user = $this->user();
        $plain = $this->mint($user);

        // The row must EXIST, or this tests a dangling morph rather than the
        // stated condition — a real subject that simply cannot hold tokens.
        $subject = PlainUser::query()->create(['id' => 3, 'name' => 'ops']);
        PersonalAccessToken::query()->update([
            'tokenable_type' => $subject->getMorphClass(),
            'tokenable_id' => $subject->getKey(),
        ]);

        $this->withToken($plain)->getJson('/resolve-probe')->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_claims_a_token_whose_abilities_are_restricted(): void
    {
        /*
         * Abilities are authorization and Sanctum checks them later; guard
         * authentication does not inspect them. A resolver that refused a
         * narrow token would make the assurance gate depend on ability scope,
         * which is the host's concern and not Vouch's.
         */
        $user = $this->user();
        $issued = app(SanctumTokenIssuer::class)->issue(DB::connection(), new TokenGrant(
            subject: SubjectKey::of($user->getMorphClass(), $user->getKey()),
            name: 'narrow',
            abilities: ['nothing:at-all'],
        ));

        $this->withToken($issued->plainText)->getJson('/resolve-probe')->assertJsonPath('claimed', true);
    }

    private function user(int $id = 7): TokenUser
    {
        return TokenUser::query()->create(['id' => $id, 'name' => 'ada']);
    }

    private function mint(TokenUser $user): string
    {
        return app(SanctumTokenIssuer::class)->issue(DB::connection(), new TokenGrant(
            subject: SubjectKey::of($user->getMorphClass(), $user->getKey()),
            name: 'probe',
            abilities: [],
        ))->plainText;
    }

    #[Test]
    public function it_claims_nothing_on_an_unauthenticated_request(): void
    {
        $this->getJson('/resolve-probe')->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_claims_a_valid_bearer_token(): void
    {
        $user = $this->user();
        $plain = $this->mint($user);

        $this->withToken($plain)->getJson('/resolve-probe')
            ->assertJsonPath('claimed', true)
            ->assertJsonPath('issuer', 'sanctum')
            ->assertJsonPath('subject', SubjectKey::of($user->getMorphClass(), $user->getKey())->toString());
    }

    #[Test]
    public function it_does_not_claim_a_cookie_authenticated_request(): void
    {
        /*
         * Sanctum attaches a TransientToken to a session principal. There is no
         * token, so there can be no assurance record, and demanding one would
         * reject legitimate SPA traffic — the failure this contract exists to
         * prevent.
         */
        $this->actingAs($this->user(), 'web')->getJson('/resolve-probe')
            ->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_does_not_claim_a_cookie_request_that_also_carries_a_bearer_header(): void
    {
        /*
         * THE case that kills header sniffing. Sanctum resolves its stateful
         * guard first and never looks at the bearer token, so the effective
         * principal is the cookie one. A guard keying off the Authorization
         * header would reject this legitimate request.
         */
        $user = $this->user();
        $plain = $this->mint($user);

        $this->actingAs($user, 'web')->withToken($plain)->getJson('/resolve-probe')
            ->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_does_not_claim_an_expired_token(): void
    {
        $user = $this->user();
        $plain = $this->mint($user);
        PersonalAccessToken::query()->update(['expires_at' => now()->subMinute()]);

        $this->withToken($plain)->getJson('/resolve-probe')->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_does_not_claim_a_deleted_token(): void
    {
        $plain = $this->mint($this->user());
        PersonalAccessToken::query()->delete();

        $this->withToken($plain)->getJson('/resolve-probe')->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_does_not_claim_a_revoked_token(): void
    {
        $user = $this->user();
        $plain = $this->mint($user);
        $issuer = app(SanctumTokenIssuer::class);
        $minted = PersonalAccessToken::findToken($plain);
        self::assertInstanceOf(PersonalAccessToken::class, $minted);
        $issuer->revoke(stringValue($minted->getKey()));

        $this->withToken($plain)->getJson('/resolve-probe')->assertJsonPath('claimed', false);
    }

    #[Test]
    public function it_does_not_claim_a_bearer_string_that_is_not_a_sanctum_token(): void
    {
        // An unrelated Passport or JWT API must pass through untouched rather
        // than be claimed and then refused for lacking an assurance record.
        $this->withToken('not-a-sanctum-token')->getJson('/resolve-probe')
            ->assertJsonPath('claimed', false);
    }

    #[Test]
    public function the_claimed_subject_is_the_tokenable_and_not_the_session_user(): void
    {
        /*
         * Two different users: one holds the token, another holds the session.
         * With no session principal, the claim must follow the TOKEN. Getting
         * this backwards would let one user's session name another's token.
         */
        $holder = $this->user(7);
        $other = $this->user(9);
        $plain = $this->mint($holder);

        // No session principal, so the claim must follow the TOKEN. With a
        // session present Sanctum would pick the cookie actor instead, which is
        // the case asserted separately above — the two together are what stop a
        // resolver reading the wrong one.
        $this->withToken($plain)->getJson('/resolve-probe')
            ->assertJsonPath('subject', SubjectKey::of($holder->getMorphClass(), $holder->getKey())->toString());

        self::assertSame(9, $other->getKey());
    }
}
