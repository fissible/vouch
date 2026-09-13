<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Sessions;

use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Http\FlowResultHandler;
use Fissible\Vouch\Http\Middleware\ValidatesVouchSession;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Sessions\SessionRebinder;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session as SessionContract;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Http\Request;
use Illuminate\Session\Store;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Issue #30 — the ownership marker has to survive a whole login, not establish().
 *
 * `SessionLifecycle::establish()` regenerates the session id and writes the row.
 * Production does not stop there: `FlowResultHandler` then calls the host guard,
 * which MIGRATES the session and rotates its id again, and only afterwards does
 * `SessionRebinder` move the row onto the new binding.
 *
 * So a marker written once inside the lifecycle, bound to the id current at that
 * moment, is stale before the user's next request. An implementation like that
 * satisfies every middleware test written against `establish()` alone and locks
 * the user out of the session they just created.
 *
 * These tests span that seam: complete a login through the real handler, then
 * validate the session the way the middleware does on the following request.
 */
final class MarkerAcrossLoginTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

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

        AuthPolicy::query()->create([
            'tenant_id' => null,
            'scope' => 'login',
            'document' => ['all_of' => ['password']],
            'posture' => 'friendly',
        ]);
    }

    #[Test]
    public function a_completed_login_leaves_a_session_the_middleware_accepts(): void
    {
        /*
         * The composition test. A marker written only by the lifecycle points
         * at the id the guard replaced moments later, so this is where such an
         * implementation fails — on the user's first request after logging in.
         */
        $this->completeLogin();

        self::assertTrue(
            $this->middlewarePasses(),
            'The session this login created is refused on the very next request.',
        );

        self::assertTrue(
            AuthSession::query()->where('session_binding', $this->currentBinding())
                ->whereNull('revoked_at')->exists(),
            'The row the middleware looked for is not the one this login wrote.',
        );
    }

    #[Test]
    public function re_authenticating_on_one_device_leaves_a_session_the_middleware_accepts(): void
    {
        // The second rotation, through the same composition: logging in again
        // must not strand the user on the session they just made.
        $this->completeLogin();
        $first = $this->currentBinding();

        $this->completeLogin();

        self::assertNotSame($first, $this->currentBinding());
        self::assertTrue($this->middlewarePasses());
    }

    #[Test]
    public function re_authenticating_on_one_device_leaves_one_live_row_for_it(): void
    {
        /*
         * Per-session rows must not become per-login rows. The previous session
         * no longer exists once the id rotates, so leaving its row live would
         * grow a set of sessions nobody holds for anyone who signs in daily.
         */
        $this->completeLogin();
        $first = $this->currentBinding();

        $this->completeLogin();

        self::assertSame(
            1,
            AuthSession::query()->where('user_id', 7)->whereNull('revoked_at')->count(),
            'Re-authenticating left more than one live row for a single device.',
        );

        self::assertNotNull(
            AuthSession::query()->where('session_binding', $first)->value('revoked_at'),
            'The superseded session was left live.',
        );
    }

    #[Test]
    public function the_marker_survives_being_saved_and_reloaded(): void
    {
        /*
         * A marker held only in memory satisfies anything that never crosses a
         * request boundary. Saving and reloading is what the next request does.
         */
        $this->completeLogin();

        $store = $this->hostStore();
        $id = $store->getId();
        $store->save();

        $reloaded = new Store('vouch-reload', $store->getHandler(), $id);
        $reloaded->start();

        self::assertNotSame([], $reloaded->all(), 'Nothing was persisted to reload.');
        self::assertTrue($this->middlewarePasses($reloaded));
    }

    #[Test]
    public function a_second_device_does_not_disturb_the_first(): void
    {
        /*
         * The defect itself, through the real path. The first device's row used
         * to be rebound away by the second login, leaving it unrevocable.
         */
        $this->completeLogin();
        $first = $this->currentBinding();

        // A separate device: a fresh host session, same user.
        $this->hostStore()->flush();
        $this->hostStore()->regenerate();

        $this->completeLogin();

        self::assertNotSame($first, $this->currentBinding());
        self::assertTrue(
            AuthSession::query()->where('session_binding', $first)->whereNull('revoked_at')->exists(),
            'The first device lost its row when a second device logged in.',
        );
    }

    private function completeLogin(): void
    {
        session()->start();

        $binding = str_repeat('c', 64);
        $handle = $this->beginFlow($binding);

        app(AuthFlow::class)->advance(
            new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], $binding),
        );

        $result = app(AuthFlow::class)->advance(
            new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], $binding),
        );

        $this->handler()->handle($result);
    }

    private function beginFlow(string $binding): string
    {
        $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], $binding));

        if (! $begun instanceof Continuing || $begun->handle === null) {
            throw new RuntimeException('The flow did not begin with a continuing handle.');
        }

        return $begun->handle;
    }

    private function handler(): FlowResultHandler
    {
        $guard = auth()->guard('web');
        $session = session()->driver();

        if (! $guard instanceof StatefulGuard) {
            throw new RuntimeException('The web guard is not stateful.');
        }

        if (! $session instanceof SessionContract) {
            throw new RuntimeException('The session driver is not a session.');
        }

        return new FlowResultHandler(
            app(SessionLifecycle::class),
            app(GraceGuard::class),
            $guard,
            $session,
            app(SessionRebinder::class),
        );
    }

    private function hostStore(): Store
    {
        $store = session()->driver();

        if (! $store instanceof Store) {
            throw new RuntimeException('The session driver is not a store.');
        }

        return $store;
    }

    private function currentBinding(): string
    {
        return SessionBinding::for($this->hostStore()->getId(), BindingDomain::Session);
    }

    /** Run the middleware the way the next request would, and report the verdict. */
    private function middlewarePasses(?Store $store = null): bool
    {
        $request = Request::create('/dashboard');
        $request->setLaravelSession($store ?? $this->hostStore());

        $reached = false;

        $response = app(ValidatesVouchSession::class)->handle(
            $request,
            static function () use (&$reached): Response {
                $reached = true;

                return new Response('ok');
            },
        );

        if (! $reached) {
            self::assertNotSame(200, $response->getStatusCode(), 'A refusal returned 200.');
        }

        return $reached;
    }
}
