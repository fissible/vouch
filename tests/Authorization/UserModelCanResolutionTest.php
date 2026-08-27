<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Tests\Support\Authorization\Models\AliasedProbeUser;
use Fissible\Vouch\Tests\Support\Authorization\Models\BouncerProbeUser;
use Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
use Fissible\Vouch\Tests\Support\Authorization\Models\SpatieProbeUser;
use Fissible\Vouch\Tests\Support\Authorization\RecordingClipboard;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Contracts\Auth\Access\Authorizable;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\Attributes\Test;
use ReflectionMethod;
use Silber\Bouncer\Bouncer;
use Silber\Bouncer\BouncerServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Task 5a probe 2: which `can()` does a user model actually call?
 *
 * Source reading shows Bouncer's `Authorizable` trait overrides
 * `can`/`cant`/`cannot` and goes to the Clipboard rather than the Gate. What
 * it cannot show is what a real model composed from these traits resolves to,
 * because that depends on PHP's trait precedence rules and on whichever
 * `insteadof` a host writes.
 *
 * The discriminator is the ability callback: a Gate-routed `can()` reaches it,
 * a Clipboard-routed one never does. Bouncer's clipboard is swapped for a
 * recorder so neither path needs Bouncer's tables, and the recorder logs which
 * of its two entry points was used — `check()` is the trait's, `checkGetId()`
 * is the Gate hook's.
 *
 * spatie's Gate hook is switched off here — not to dodge a result, but
 * because it calls `checkPermissionTo()`, which queries spatie's tables on
 * every Gate check and would make this probe measure schema rather than
 * dispatch. {@see GateHookRegistrationProbeCase} characterises that hook.
 */
final class UserModelCanResolutionTest extends TestCase
{
    private RecordingClipboard $clipboard;

    /** @var list<string> */
    private array $calls = [];

    protected function setUp(): void
    {
        parent::setUp();

        $this->clipboard = new RecordingClipboard;
        $this->app?->make(Bouncer::class)->setClipboard($this->clipboard);

        Gate::define('probe.ability', function (Authorizable $user): bool {
            $this->calls[] = 'gate:ability';

            return false;
        });
    }

    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            BouncerServiceProvider::class,
            PermissionServiceProvider::class,
            VouchServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('permission.register_permission_check_method', false);
    }

    #[Test]
    public function a_stock_laravel_user_routes_can_through_the_gate(): void
    {
        (new PlainProbeUser)->can('probe.ability');

        self::assertSame(['gate:ability'], $this->trace());
    }

    #[Test]
    public function a_spatie_user_still_routes_can_through_the_gate(): void
    {
        // spatie's HasRoles adds hasPermissionTo()/checkPermissionTo(); it
        // never declares can(), so the inherited Gate delegation survives.
        (new SpatieProbeUser)->can('probe.ability');

        self::assertSame(['gate:ability'], $this->trace());
    }

    #[Test]
    public function a_bouncer_user_bypasses_the_gate_entirely(): void
    {
        (new BouncerProbeUser)->can('probe.ability');

        self::assertSame(['clipboard:check'], $this->trace());
    }

    #[Test]
    public function bouncers_trait_overrides_the_inherited_method_with_no_collision(): void
    {
        // The override is silent. Illuminate's Authorizable is used by the
        // PARENT class, and a trait used in the child wins over an inherited
        // method, so nothing in PHP reports a conflict — the model simply
        // stops being enforceable at the Gate.
        $declaring = new ReflectionMethod(BouncerProbeUser::class, 'can')->getDeclaringClass()->getName();

        self::assertSame(BouncerProbeUser::class, $declaring);
        self::assertContains(
            'Silber\Bouncer\Database\Concerns\Authorizable',
            class_uses(BouncerProbeUser::class),
        );
    }

    #[Test]
    public function an_explicitly_aliased_model_routes_can_through_the_gate(): void
    {
        (new AliasedProbeUser)->can('probe.ability');

        self::assertSame(['gate:ability'], $this->trace());
    }

    #[Test]
    public function the_aliased_model_keeps_bouncers_check_reachable_under_another_name(): void
    {
        (new AliasedProbeUser)->bouncerCan('probe.ability');

        self::assertSame(['clipboard:check'], $this->trace());
    }

    #[Test]
    public function cant_and_cannot_follow_whichever_can_the_model_resolved(): void
    {
        (new PlainProbeUser)->cannot('probe.ability');
        self::assertSame(['gate:ability'], $this->trace());

        $this->reset();

        (new BouncerProbeUser)->cannot('probe.ability');
        self::assertSame(['clipboard:check'], $this->trace());
    }

    #[Test]
    public function can_any_is_gate_routed_on_every_model_because_bouncer_never_overrides_it(): void
    {
        // spatie's PermissionMiddleware calls canAny(). Bouncer's trait does
        // not declare it, so even a Bouncer-trait model reaches the Gate on
        // that path — the bypass is per-method, not per-model. A model whose
        // can() is unenforceable therefore still has an enforceable canAny().
        (new BouncerProbeUser)->canAny(['probe.ability']);

        self::assertSame(['gate:ability'], $this->trace());
    }

    /**
     * @return list<string>
     */
    private function trace(): array
    {
        return [...$this->clipboard->calls, ...$this->calls];
    }

    private function reset(): void
    {
        $this->clipboard->calls = [];
        $this->calls = [];
    }
}
