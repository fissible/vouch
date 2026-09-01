<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Sessions;

use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Http\FlowResultHandler;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Sessions\SessionRebinder;
use Fissible\Vouch\Tests\Support\Sessions\FailingLoginGuard;
use Fissible\Vouch\Tests\Support\Tokens\TokenUser;
use Fissible\Vouch\Tests\Support\Tokens\UsesSanctumSchema;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Contracts\Auth\StatefulGuard;
use Fissible\Vouch\Flow\Continuing;
use Illuminate\Contracts\Session\Session as SessionContract;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Laravel\Sanctum\SanctumServiceProvider;
use PHPUnit\Framework\Attributes\Test;
use RuntimeException;
use Throwable;

/**
 * Issue #21 — the session a login writes must be the session the user ends up with.
 *
 * `FlowResultHandler::establish()` wrote `auth_sessions.session_binding` and then
 * called `loginUsingId()`, which calls `login()`, which calls `regenerate(true)`,
 * which calls `migrate(true)` — regenerating the id AGAIN. The binding described a session that no longer existed, and
 * nothing rebound it.
 *
 * Every session lookup in the package goes through
 * `SessionBinding::for($currentId, ...)`, so the row was orphaned for the rest
 * of that session: no Vouch session on assurance-gated routes, and issuance
 * refusing with "requires the authenticated host session".
 *
 * It survived because every other fixture builds its session directly, where
 * nothing migrates afterwards and the binding matches by construction. These
 * tests span the seam that skips: complete a login through the real handler,
 * then look the session up the way production does.
 *
 * The ordering it must NOT trade away is the reason the bug existed. The record
 * is written before the host guard is invoked, so a failed record write never
 * produces a logged-in user. The rebind is therefore a third step of the same
 * protocol rather than a reordering, and the guard login plus the rebind form
 * one commit boundary: a failure in either must leave nobody authenticated.
 *
 * "Commit boundary" here means COMPENSATED logical atomicity, not a database
 * transaction. The host session and `auth_sessions` share none, so the property
 * is maintained by compensating rather than by rolling back.
 */
final class LoginCompletionTest extends TestCase
{
    use DatabaseMigrations;
    use UsesSanctumSchema;

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
        TokenUser::query()->create(['id' => 8, 'name' => 'grace']);
        AuthIdentifier::create([
            'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
        ]);
        app(PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
        AuthPolicy::query()->create([
            'tenant_id' => null, 'scope' => 'login',
            'document' => ['all_of' => ['password']], 'posture' => 'friendly',
        ]);
    }

    private function handler(?StatefulGuard $guard = null, ?SessionRebinder $rebinder = null): FlowResultHandler
    {
        return new FlowResultHandler(
            app(SessionLifecycle::class),
            app(GraceGuard::class),
            // Constructed rather than resolved: the handler needs a
            // StatefulGuard, which the test container does not bind.
            $guard ?? self::webGuard(),
            self::hostSession(),
            $rebinder ?? app(SessionRebinder::class),
        );
    }

    private function completeLogin(?StatefulGuard $guard = null, ?SessionRebinder $rebinder = null): void
    {
        session()->start();

        $binding = str_repeat('c', 64);
        $handle = self::beginFlow($binding);

        app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], $binding));
        $result = app(AuthFlow::class)->advance(
            new FlowRequest($handle, 'submit', ['password' => 'correct horse battery staple'], $binding),
        );

        $this->handler($guard, $rebinder)->handle($result);
    }


    /**
     * The narrowing these three helpers exist for is deliberate.
     *
     * auth()->guard() returns Guard, session()->driver() returns a manager's
     * driver, and FlowResult is a MARKER interface — none of them promises what
     * this file needs. Annotating the production types to suit a test would
     * assert something false about every other implementation, so the test
     * narrows instead and fails loudly if the assumption stops holding.
     */
    private static function webGuard(): StatefulGuard
    {
        $guard = auth()->guard('web');

        if (! $guard instanceof StatefulGuard) {
            throw new RuntimeException('The web guard is not stateful.');
        }

        return $guard;
    }

    private static function hostSession(): SessionContract
    {
        $session = session()->driver();

        if (! $session instanceof SessionContract) {
            throw new RuntimeException('The session driver is not a session.');
        }

        return $session;
    }

    /** @param array<string, mixed> $extra */
    private static function beginFlow(string $binding, array $extra = []): string
    {
        $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', $extra, $binding));

        if (! $begun instanceof Continuing || $begun->handle === null) {
            throw new RuntimeException('The flow did not begin with a continuing handle.');
        }

        return $begun->handle;
    }

    private function currentBinding(): string
    {
        return SessionBinding::for(session()->getId(), BindingDomain::Session);
    }

    #[Test]
    public function the_session_is_findable_the_way_production_looks_it_up(): void
    {
        /*
         * Asserted as a LOOKUP rather than a field comparison, because the
         * lookup is what every consumer performs: ValidatesVouchSession, the
         * grace guard, and issuance all resolve by binding. A test that
         * compared columns could pass while the query nobody wrote still
         * returned nothing.
         */
        $this->completeLogin();

        self::assertSame(
            1,
            AuthSession::query()->where('session_binding', $this->currentBinding())->count(),
            'The session written by the login cannot be found by its own binding.',
        );
    }

    #[Test]
    public function the_login_leaves_exactly_one_session_for_the_subject(): void
    {
        /*
         * The rebind must move the row the login created, not create a second
         * one. Two rows would leave the earlier binding unrevocable — the
         * failure 2.1 shipped a row-count test to prevent, reached here by a
         * different route.
         */
        $this->completeLogin();

        self::assertSame(1, AuthSession::query()->where('user_id', 7)->count());
    }

    #[Test]
    public function the_rebind_does_not_disturb_another_subjects_session(): void
    {
        /*
         * A late UPDATE that matched too broadly would rebind a sibling's live
         * session to this login's id, handing one user another's session row.
         * The rebind must be scoped to the row this login created.
         */
        $other = AuthSession::query()->create([
            'user_id' => 8,
            'session_binding' => str_repeat('9', 64),
            'amr' => ['pwd'],
            'acr' => 'aal1',
            'assurance_proof' => sessionProof(8, 'aal1'),
            'weakest_satisfied_at' => now(),
        ]);

        $this->completeLogin();

        self::assertSame(
            str_repeat('9', 64),
            stringValue($other->refresh()->session_binding),
        );
    }

    #[Test]
    public function the_rebind_does_not_disturb_the_subjects_own_revoked_session(): void
    {
        /*
         * The sibling test rules out matching another USER. This rules out
         * matching too broadly within the same one: a rebind scoped to
         * `user_id = 7` rather than to the binding this login created would
         * rewrite a revoked row's binding. That does not make it live —
         * `revoked_at` stays set — but it is still wrong in two ways: it can
         * collide with the unique binding the live row needs, and it points a
         * revoked record at the session the user is actually holding.
         */
        $revoked = AuthSession::query()->create([
            'user_id' => 7,
            'session_binding' => str_repeat('7', 64),
            'amr' => ['pwd'],
            'acr' => 'aal1',
            'assurance_proof' => sessionProof(7, 'aal1'),
            'weakest_satisfied_at' => now(),
            'revoked_at' => now(),
        ]);

        $this->completeLogin();

        self::assertSame(str_repeat('7', 64), stringValue($revoked->refresh()->session_binding));
        self::assertNotNull($revoked->refresh()->revoked_at);
    }

    #[Test]
    public function a_failed_host_login_leaves_nobody_authenticated(): void
    {
        /*
         * The compensation path. The guard login and the rebind are one commit
         * boundary: once the login has been attempted, a failure cannot return
         * a successful result and leave a usable session behind.
         *
         * The row may survive if the database is the failed dependency — it
         * cannot be helped and it does not matter, PROVIDED it cannot
         * authorize. That is the assertion below: whatever remains must not
         * match the session the caller is left holding.
         */
        $guard = new FailingLoginGuard(self::webGuard());

        /*
         * The ordering discriminator. A handler that logged in BEFORE writing
         * the record would arrive here with no row, and a double that only
         * threw could not tell that apart from the correct order.
         */
        $observedRow = null;
        $guard->onLogin = static function () use (&$observedRow): void {
            $observedRow = AuthSession::query()->where('user_id', 7)->whereNull('revoked_at')->count();
        };

        $threw = false;

        try {
            $this->completeLogin($guard);
        } catch (Throwable) {
            $threw = true;
        }

        self::assertSame(1, $observedRow, 'The record must already exist when the host guard is invoked.');
        self::assertTrue($threw, 'A failed host login must not return a successful result.');
        self::assertFalse(auth()->check(), 'A failed login must leave nobody authenticated.');

        /*
         * Through the INJECTED guard. Compensating via ambient auth() would
         * pass this fixture and fail a host whose guard is not the default —
         * which is exactly the host that configured one deliberately.
         */
        self::assertTrue($guard->loggedOut, 'Compensation must use the guard it was given.');
        self::assertSame(
            0,
            AuthSession::query()->where('session_binding', $this->currentBinding())->count(),
            'A session left behind by a failed login must not be reachable from the current session.',
        );
    }

    #[Test]
    public function a_failed_rebind_after_a_successful_login_leaves_nobody_authenticated(): void
    {
        /*
         * The window that actually matters, and the one the guard double above
         * cannot reach: the host login SUCCEEDED and regenerated the session,
         * and the rebind then failed. That is the only state where a user is
         * authenticated against a session whose record cannot be found.
         *
         * It needs a seam. Failing the rebind through a query trap or an
         * Eloquent event would couple this test to a chosen persistence shape,
         * so the rebind is a collaborator the handler takes and this doubles it.
         * That is a requirement on the implementation, stated here rather than
         * discovered later.
         */
        /*
         * The double asserts the state it is called in, then fails. Without
         * these checks it would prove only that SOMETHING called rebind: an
         * implementation that called it before the login, or with an arbitrary
         * binding, would satisfy a double that merely threw.
         */
        $rebinder = new class implements SessionRebinder {
            /** @var array<string, mixed> */
            public array $observed = [];

            public function rebind(string $previousBinding, int $userId): void
            {
                $this->observed = [
                    'authenticated' => auth()->check(),
                    'userId' => $userId,
                    'migrated' => SessionBinding::for(session()->getId(), BindingDomain::Session) !== $previousBinding,
                    /*
                     * Scoped to the subject as well as the binding: an
                     * arbitrary existing binding — another user's — would
                     * satisfy a check on the binding alone.
                     */
                    'rowStillHasPrevious' => AuthSession::query()
                        ->where('user_id', 7)
                        ->where('session_binding', $previousBinding)
                        ->exists(),
                ];

                throw new RuntimeException('the rebind failed');
            }
        };

        $threw = false;

        try {
            $this->completeLogin(rebinder: $rebinder);
        } catch (Throwable) {
            $threw = true;
        }

        self::assertSame(
            [
                'authenticated' => true,
                'userId' => 7,
                'migrated' => true,
                'rowStillHasPrevious' => true,
            ],
            $rebinder->observed,
            'The rebind must run after a successful login, for this subject, with the '
            . 'binding the row actually still carries.',
        );
        self::assertTrue($threw, 'A failed rebind must not return a successful result.');
        self::assertFalse(auth()->check(), 'A failed rebind must leave nobody authenticated.');
        self::assertSame(
            0,
            AuthSession::query()->where('session_binding', $this->currentBinding())->count(),
        );
    }

    #[Test]
    public function the_rebinder_leaves_a_revoked_target_row_alone(): void
    {
        /*
         * The live-state predicate, exercised directly rather than inferred.
         *
         * The other revoked-row test uses a DIFFERENT binding, so an
         * implementation matching on `user_id + previousBinding` alone would
         * pass it while still lacking the predicate. Here the exact row the
         * rebinder is told to move is revoked first, so only an implementation
         * that also requires the row to be live leaves it untouched.
         */
        $revoked = AuthSession::query()->create([
            'user_id' => 7,
            'session_binding' => str_repeat('5', 64),
            'amr' => ['pwd'],
            'acr' => 'aal1',
            'assurance_proof' => sessionProof(7, 'aal1'),
            'weakest_satisfied_at' => now(),
            'revoked_at' => now(),
        ]);

        session()->start();

        /*
         * And it REFUSES rather than doing nothing. A rebinder that ignored an
         * update count of zero would let the handler return authenticated with
         * no record for the current session — the original bug, reached by a
         * narrower path: a provisional row concurrently revoked or deleted
         * between establish() and the rebind.
         *
         * Throwing is what puts the handler's existing compensation on the
         * hook, so the user is logged out rather than left in that state.
         */
        $refused = false;

        try {
            app(SessionRebinder::class)->rebind(str_repeat('5', 64), 7);
        } catch (Throwable) {
            $refused = true;
        }

        self::assertTrue($refused, 'Rebinding a revoked row must refuse rather than silently do nothing.');

        self::assertSame(str_repeat('5', 64), stringValue($revoked->refresh()->session_binding));

        /*
         * And it did not "helpfully" create one instead. A rebinder that
         * inserted a live row when its target was missing or revoked would
         * leave the protected row untouched and still manufacture a session
         * nobody authenticated — passing the assertion above while doing the
         * worse thing.
         */
        self::assertSame(1, AuthSession::query()->count());
        self::assertSame(0, AuthSession::query()->where('session_binding', $this->currentBinding())->count());
    }

    #[Test]
    public function the_rebinder_will_not_move_another_subjects_row(): void
    {
        /*
         * Subject scoping proved AT THE REBINDER, not at its caller. The double
         * in the compensation test shows the handler passes the right userId;
         * it says nothing about whether the concrete rebinder uses it. A
         * rebinder matching on previousBinding alone passes every other test
         * here, and would hand one user another's session row.
         */
        $other = AuthSession::query()->create([
            'user_id' => 8,
            'session_binding' => str_repeat('4', 64),
            'amr' => ['pwd'],
            'acr' => 'aal1',
            'assurance_proof' => sessionProof(8, 'aal1'),
            'weakest_satisfied_at' => now(),
        ]);

        session()->start();

        $refused = false;

        try {
            app(SessionRebinder::class)->rebind(str_repeat('4', 64), 7);
        } catch (Throwable) {
            $refused = true;
        }

        self::assertTrue($refused, "Rebinding another subject's row must refuse rather than silently do nothing.");

        self::assertSame(str_repeat('4', 64), stringValue($other->refresh()->session_binding));
        self::assertSame(1, AuthSession::query()->count());
        self::assertSame(0, AuthSession::query()->where('user_id', 7)->count());
    }

    #[Test]
    public function a_host_login_that_returns_false_is_a_failure_too(): void
    {
        /*
         * StatefulGuard::loginUsingId() returns the authenticated user on
         * success and false only when its provider cannot resolve the id — it
         * does not throw. That is the failure most likely to be
         * treated as success, because nothing forces the caller to look, and
         * the result would be a rebound row and an "authenticated" response
         * while the host remains a guest.
         */
        $guard = new FailingLoginGuard(self::webGuard(), throw: false);

        $threw = false;

        try {
            $this->completeLogin($guard);
        } catch (Throwable) {
            $threw = true;
        }

        self::assertTrue($threw, 'A login returning false must not be treated as success.');
        self::assertFalse(auth()->check());
        self::assertTrue($guard->loggedOut, 'Compensation must use the guard it was given.');
        self::assertSame(
            0,
            AuthSession::query()->where('session_binding', $this->currentBinding())->count(),
        );
    }

    #[Test]
    public function a_second_login_rotates_rather_than_accumulating(): void
    {
        /*
         * The rebind must not turn re-authentication into row growth. Rotation
         * in place is the shipped contract; this proves the new step preserves
         * it across the migration boundary rather than only on a first login.
         */
        $this->completeLogin();
        $first = $this->currentBinding();

        $this->completeLogin();

        self::assertSame(1, AuthSession::query()->where('user_id', 7)->count());
        self::assertNotSame($first, $this->currentBinding());
        self::assertSame(
            1,
            AuthSession::query()->where('session_binding', $this->currentBinding())->count(),
        );
    }
}
