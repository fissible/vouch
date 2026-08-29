<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\Authorization\Models\PermissionedProbeUser;
use Fissible\Vouch\Tests\Support\Authorization\Models\RoleBearingProbeUser;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Auth\User as BaseUser;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\Test;
use Spatie\Permission\Middleware\PermissionMiddleware;
use Spatie\Permission\Middleware\RoleOrPermissionMiddleware;
use Spatie\Permission\PermissionServiceProvider;

/**
 * End-to-end enforcement through the real HTTP stack (2.3d Task 5b).
 *
 * Every other test in this feature invokes a class directly. This one drives
 * actual routed requests, because the thing being claimed is a claim about
 * ORDERING inside Laravel's middleware pipeline — and an implementation can
 * satisfy every unit test while the deployed route still fails open.
 *
 * The fail-open being closed is the one Task 5a measured: spatie's
 * `Gate::before` hook grants whenever the user holds the permission, which
 * short-circuits every hook registered after it. So the proof has to be that a
 * user who genuinely HOLDS the permission is still refused when their
 * assurance is short.
 */
final class AbilityAssuranceRouteTest extends TestCase
{
    use RefreshDatabase;

    /**
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            PermissionServiceProvider::class,
            VouchServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('auth.providers.users.model', PermissionedProbeUser::class);
        $app['config']->set('vouch.step_up.presentation_url', '/auth/step-up');
        $app['config']->set('vouch.assurance_requirements', ['invoices.approve' => 'aal2']);
        $app['config']->set('vouch_test.held_permissions', ['invoices.approve']);
        $app['config']->set('vouch_test.held_roles', []);
    }

    protected function setUp(): void
    {
        parent::setUp();

        /*
         * Aliased here because a HOST has to alias it: spatie ships no
         * middleware aliases of its own on Laravel 11+, so `permission:` only
         * resolves once bootstrap/app.php names it. Without this the routes
         * below abort on an unresolvable middleware before either package
         * runs, and the whole file would prove nothing while looking green.
         */
        $router = app('router');
        $router->aliasMiddleware('permission', PermissionMiddleware::class);
        $router->aliasMiddleware('role_or_permission', RoleOrPermissionMiddleware::class);
        $router->aliasMiddleware('perm', PermissionMiddleware::class);

        Route::middleware('web')->post('/spatie/approve', fn (): string => 'controller reached')
            ->middleware('permission:invoices.approve');

        Route::middleware('web')->post('/gate/approve', fn (): string => 'controller reached')
            ->middleware('can:invoices.approve');

        Route::middleware('web')->post('/gate/view', fn (): string => 'controller reached')
            ->middleware('can:invoices.view');

        Route::middleware('api')->post('/api/approve', fn (): string => 'controller reached')
            ->middleware('permission:invoices.approve');

        Route::middleware('web')->post('/aliased/approve', fn (): string => 'controller reached')
            ->middleware('perm:invoices.approve');

        Route::middleware('web')->post('/either/approve', fn (): string => 'controller reached')
            ->middleware('role_or_permission:admin|invoices.approve');

        // No authorization middleware at all: the ability is checked INSIDE
        // the action, which is the only shape the route scanner cannot see.
        Route::middleware('web')->post('/gate/direct', fn (): string => Gate::allows('invoices.approve') ? 'allowed' : 'denied');
    }

    #[Test]
    public function a_low_assurance_user_who_holds_the_spatie_permission_never_reaches_the_controller(): void
    {
        // THE test. Without this middleware, spatie's before hook grants and
        // the controller runs.
        $this->signIn(acr: 'aal1');

        $response = $this->post('/spatie/approve');

        $response->assertRedirect('/auth/step-up');
        $response->assertDontSee('controller reached');
    }

    #[Test]
    public function a_low_assurance_user_the_gate_would_allow_never_reaches_the_controller(): void
    {
        Gate::define('invoices.approve', fn (): bool => true);
        $this->signIn(acr: 'aal1');

        $this->post('/gate/approve')->assertRedirect('/auth/step-up');
    }

    #[Test]
    public function it_remembers_the_refused_route_for_the_return_trip(): void
    {
        $this->signIn(acr: 'aal1');

        $this->post('/spatie/approve');

        self::assertSame('/spatie/approve', session('vouch.step_up.intended'));
    }

    #[Test]
    public function a_sufficient_user_who_holds_the_permission_reaches_the_controller(): void
    {
        $this->signIn(acr: 'aal2');

        $this->post('/spatie/approve')->assertOk()->assertSee('controller reached');
    }

    #[Test]
    public function a_stronger_session_satisfies_a_weaker_requirement(): void
    {
        $this->signIn(acr: 'aal3');

        $this->post('/spatie/approve')->assertOk();
    }

    #[Test]
    public function sufficient_assurance_does_not_substitute_for_the_hosts_grant(): void
    {
        /*
         * Deny only, proven end to end. The user's assurance is more than
         * enough, but they do not hold the permission — so the request must
         * still be refused by the AUTHORIZATION layer. If Vouch ever granted,
         * this is the test that would catch it.
         */
        config(['vouch_test.held_permissions' => []]);
        $this->signIn(acr: 'aal3');

        $this->post('/spatie/approve')->assertForbidden();
    }

    #[Test]
    public function a_route_whose_ability_is_not_mapped_is_untouched(): void
    {
        Gate::define('invoices.view', fn (): bool => true);
        $this->signIn(acr: 'aal0');

        $this->post('/gate/view')->assertOk()->assertSee('controller reached');
    }

    #[Test]
    public function a_guest_is_refused_by_authorization_rather_than_stranded_at_step_up(): void
    {
        /*
         * Vouch's middleware sits in the `web` group, ahead of `auth`. A guest
         * has no assurance and cannot acquire any without logging in first, so
         * sending them to step-up would strand them. Letting them past is not
         * a bypass — the authorization layer below refuses every guest.
         */
        $this->post('/gate/approve')->assertForbidden();
    }

    #[Test]
    public function an_api_route_with_no_session_is_refused_rather_than_allowed(): void
    {
        /*
         * Session-sourced until 2.4. A token request cannot prove assurance
         * today, so a mapped ability on an API route is STATED as refused
         * rather than failing open. 2.4's RFC 9470 work supplies the token
         * vocabulary; this must not invent a second one in the meantime.
         */
        $this->actingAs($this->probeUser())
            ->postJson('/api/approve')
            ->assertForbidden()
            ->assertJsonPath('error', 'insufficient_assurance');
    }

    #[Test]
    public function an_api_route_whose_ability_is_not_mapped_still_works(): void
    {
        config(['vouch.assurance_requirements' => []]);

        $this->actingAs($this->probeUser())->postJson('/api/approve')->assertOk();
    }

    #[Test]
    public function the_gate_hook_refuses_a_direct_authorization_call_the_middleware_never_sees(): void
    {
        /*
         * Defense in depth, and the only part of this feature that covers a
         * `Gate::allows()` written inside a controller. It is NOT the primary
         * mechanism: probe 1 measured that this hook lands last and that
         * spatie's grant short-circuits it, which is why the route tests above
         * exist. Here nothing grants first, so the hook is reached.
         */
        // Asserted through a REQUEST, not from the test body: the hook is
        // session-sourced by design and defers when there is no session
        // context (see AssuranceGateHookTest), so calling Gate::allows() from
        // the test body would prove the opposite of what it appears to.
        //
        // Nothing grants ahead of it here — spatie holds no permission, so its
        // hook defers. That is the ONLY condition under which this hook
        // decides anything, and the test below states the other half.
        config(['vouch_test.held_permissions' => []]);
        Gate::define('invoices.approve', fn (): bool => true);
        $this->signIn(acr: 'aal1');

        $this->post('/gate/direct')->assertSee('denied');
    }

    #[Test]
    public function the_gate_hook_is_bypassed_when_an_earlier_hook_grants(): void
    {
        /*
         * The measured limitation, asserted rather than described — this is
         * the survey's central finding reproduced end to end.
         *
         * The user holds the permission, so spatie's hook returns true and
         * `callBeforeCallbacks()` returns on the first non-null result. Vouch's
         * hook is registered after spatie's and never runs, so a session two
         * levels short of the requirement is ALLOWED.
         *
         * Nothing in Vouch can fix this from inside the Gate: provider order
         * comes from installed.json. It is why enforcement lives in route
         * middleware and why this hook is documented as defense in depth. If
         * this test ever starts failing, the ordering assumption the whole
         * design rests on has changed and the design should be revisited.
         */
        config(['vouch_test.held_permissions' => ['invoices.approve']]);
        Gate::define('invoices.approve', fn (): bool => true);
        $this->signIn(acr: 'aal1');

        $this->post('/gate/direct')->assertSee('allowed');
    }

    #[Test]
    public function the_gate_hook_never_grants_an_ability_the_host_withheld(): void
    {
        config(['vouch_test.held_permissions' => []]);
        Gate::define('invoices.approve', fn (): bool => false);
        $this->signIn(acr: 'aal3');

        $this->post('/gate/direct')->assertSee('denied');
    }

    #[Test]
    public function a_host_alias_for_the_authorization_middleware_is_still_enforced(): void
    {
        /*
         * Parsing an alias correctly in isolation is not enough — the parsed
         * ability has to reach enforcement on a real route. An implementation
         * that resolves aliases in the scanner but drops them on the way to
         * the comparison would pass the scanner tests and fail open here.
         */
        $this->signIn(acr: 'aal1');

        $this->post('/aliased/approve')->assertRedirect('/auth/step-up');
    }

    #[Test]
    public function the_deliberate_role_name_collision_is_enforced_on_a_real_route(): void
    {
        /*
         * `role_or_permission:admin|invoices.approve` admits on EITHER branch,
         * and Vouch cannot see which one granted — so it requires the
         * strongest mapped level among them. Fail closed.
         *
         * This user is admitted by the ROLE alone and holds no permission at
         * all, which is what makes the collision real rather than
         * hypothetical: `admin` is a role name that the map treats as an
         * ability name, and it carries the higher requirement. aal2 clears the
         * permission branch's aal2 and is still refused.
         */
        config([
            'vouch.assurance_requirements' => ['admin' => 'aal3', 'invoices.approve' => 'aal2'],
            'vouch_test.held_permissions' => [],
            'vouch_test.held_roles' => ['admin'],
        ]);

        $this->signInAs(new RoleBearingProbeUser, acr: 'aal2');

        $this->post('/either/approve')->assertRedirect('/auth/step-up');
    }

    #[Test]
    public function the_role_branch_still_admits_once_the_stronger_requirement_is_met(): void
    {
        /*
         * The other half. Without this, an implementation that simply refused
         * every `role_or_permission:` route would pass the test above, and the
         * collision policy would be indistinguishable from a blanket denial.
         * spatie's role branch really does admit here.
         */
        config([
            'vouch.assurance_requirements' => ['admin' => 'aal3', 'invoices.approve' => 'aal2'],
            'vouch_test.held_permissions' => [],
            'vouch_test.held_roles' => ['admin'],
        ]);

        $this->signInAs(new RoleBearingProbeUser, acr: 'aal3');

        $this->post('/either/approve')->assertOk()->assertSee('controller reached');
    }

    private function probeUser(): PermissionedProbeUser
    {
        $user = new PermissionedProbeUser;
        $user->id = 7;

        return $user;
    }

    private function signIn(string $acr): void
    {
        $this->signInAs($this->probeUser(), $acr);
    }

    private function signInAs(BaseUser $user, string $acr): void
    {
        $user->id = 7;
        $id = $this->pinSession();

        AuthSession::create([
            'session_binding' => SessionBinding::for($id, BindingDomain::Session),
            'user_id' => 7,
            'amr' => ['password'],
            'acr' => $acr,
            'assurance_proof' => sessionProof(7, $acr),
            'weakest_satisfied_at' => now(),
        ]);

        $this->actingAs($user);
    }
}
