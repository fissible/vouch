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
 *
 * Recorded gap: the sibling test checks that device B's ROW stays live after
 * device A re-authenticates, but does not then validate B's session through the
 * middleware. Restoring B's store to assert that would exercise the same
 * preservation the row check already covers, so it is noted rather than added.
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

    #[Test]
    public function re_authenticating_one_device_leaves_another_device_alone(): void
    {
        /*
         * The replacement branch, entered with a live sibling present -- which
         * no other fixture here does.
         *
         * "When replacing an existing session, revoke every live row for this
         * user" passes every other re-auth test in this file, because they run
         * with nothing else live. It signs the user out everywhere each time
         * they log in again, and only a sibling can show it.
         */
        $this->completeLogin();
        $deviceA = $this->hostStore()->getId();
        $firstA = $this->currentBinding();
        $this->hostStore()->save();

        $this->switchToFreshDevice();
        $this->completeLogin();
        $bindingB = $this->currentBinding();
        $this->hostStore()->save();

        // Back to the first device, which re-authenticates.
        $this->resumeDevice($deviceA);
        $this->completeLogin();

        self::assertNotSame($firstA, $this->currentBinding(), 'Device A did not rotate.');

        self::assertNotNull(
            AuthSession::query()->where('session_binding', $firstA)->value('revoked_at'),
            "Device A's previous session was left live.",
        );

        self::assertTrue($this->middlewarePasses(), "Device A's replacement was refused.");

        self::assertTrue(
            AuthSession::query()->where('session_binding', $bindingB)->whereNull('revoked_at')->exists(),
            "Device B was signed out by device A re-authenticating.",
        );
    }

    #[Test]
    public function a_refused_session_is_destroyed_rather_than_merely_redirected(): void
    {
        /*
         * Refusing once is not enough. A branch that drops the marker, redirects
         * and leaves the host authentication in place hands the NEXT request a
         * session with no marker and no record -- which passes, because that is
         * indistinguishable from a stranger's session.
         *
         * So the refusal has to end the session, not decline one request.
         */
        $this->completeLogin();

        $store = $this->hostStore();

        $authenticationKeys = array_keys(array_filter(
            $store->all(),
            static fn (mixed $value, string $key): bool => str_starts_with($key, 'login_'),
            ARRAY_FILTER_USE_BOTH,
        ));

        self::assertNotSame([], $authenticationKeys, 'The login left no host authentication to destroy.');

        AuthSession::query()->where('session_binding', $this->currentBinding())->delete();

        self::assertFalse($this->middlewarePasses(), 'A session with no record was allowed through.');

        /*
         * The host AUTHENTICATION must be gone. Asserting that no key name
         * reappears would be stricter than the contract and would reject a
         * correct refusal: invalidate() followed by regenerateToken() puts a
         * fresh _token back, which is right rather than a leak.
         */
        foreach ($authenticationKeys as $key) {
            self::assertFalse(
                $this->hostStore()->has($key),
                "The refusal left host authentication ({$key}) in place, so the next request carries it.",
            );
        }
    }

    #[Test]
    public function a_missing_record_is_refused_after_a_save_and_reload(): void
    {
        /*
         * The refusal has to survive the request boundary too. Positive
         * composition coverage alone cannot show that: a marker read from
         * memory could refuse correctly in-process and find nothing to check
         * on the next request, which then passes.
         */
        $this->completeLogin();

        $store = $this->hostStore();
        $id = $store->getId();
        $binding = $this->currentBinding();
        $store->save();

        /*
         * One ordinary accepted request in between, then saved again. This is
         * what separates a marker that PERSISTS from one merely present on the
         * request that wrote it: flash data survives exactly one request and is
         * aged away by the next, after which the session reads as a stranger's
         * -- no marker, no record -- and passes, while the host guard still
         * authenticates. Measured, an implementation storing the marker with
         * flash() satisfies every other test in this file.
         */
        $intermediate = new Store('vouch-reload', $store->getHandler(), $id);
        $intermediate->start();

        self::assertTrue(
            $this->middlewarePasses($intermediate),
            'The session was refused on an ordinary request before anything was deleted.',
        );

        $intermediate->save();

        AuthSession::query()->where('session_binding', $binding)->delete();

        $reloaded = new Store('vouch-reload', $store->getHandler(), $id);
        $reloaded->start();

        self::assertFalse(
            $this->middlewarePasses($reloaded),
            'A reloaded session whose record is gone was allowed through.',
        );
    }

    /** Begin a separate device: a fresh host session for the same user. */
    private function switchToFreshDevice(): void
    {
        $store = $this->hostStore();
        $store->flush();
        $store->regenerate();
    }

    /** Return to a device whose session was saved earlier. */
    private function resumeDevice(string $id): void
    {
        $store = $this->hostStore();
        $store->setId($id);
        $store->start();
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
