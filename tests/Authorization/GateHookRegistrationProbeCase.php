<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Tests\Support\Authorization\GateHookInspector;
use Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
use Fissible\Vouch\Tests\Support\Authorization\ProbeGateHookServiceProvider;
use Fissible\Vouch\Tests\TestCase;
use Illuminate\Auth\Access\Gate;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use PHPUnit\Framework\Attributes\Test;

/**
 * Task 5a probe 1: effective combined Gate hook registration.
 *
 * The survey established from source that `callBeforeCallbacks()` returns the
 * first non-null result in registration order. What source reading could not
 * settle is which hooks exist, and in what order, once both authorization
 * packages boot together: spatie registers through
 * `callAfterResolving(Gate::class)` while Bouncer resolves the Gate inside its
 * own `boot()`, so the answer depends on runtime resolution.
 *
 * The subclasses fix the provider order. Everything measured lives here.
 *
 * The dispatch tests below build a bare Gate rather than the container's.
 * That is deliberate: the ordering rule under test belongs to Laravel's Gate,
 * and Bouncer's registered hook would otherwise query its own tables, which
 * this probe does not migrate.
 */
abstract class GateHookRegistrationProbeCase extends TestCase
{
    private const SPATIE_HOOK = 'Spatie\Permission\PermissionRegistrar';

    private const BOUNCER_HOOK = 'Silber\Bouncer\Guard';

    #[Test]
    public function it_records_which_before_hooks_exist_and_in_what_order(): void
    {
        self::assertSame($this->expectedBeforeHooks(), GateHookInspector::before($this->containerGate()));
    }

    #[Test]
    public function bouncer_registers_an_after_hook_and_spatie_does_not(): void
    {
        self::assertSame([self::BOUNCER_HOOK], GateHookInspector::after($this->containerGate()));
    }

    #[Test]
    public function both_hooks_register_under_either_provider_order(): void
    {
        // The survey predicted spatie's callback might never register when a
        // provider booted earlier had already resolved the Gate singleton,
        // since `afterResolving` fires on resolution and a singleton resolves
        // once. It does register: `ServiceProvider::callAfterResolving()`
        // also invokes the callback immediately when `$app->resolved($name)`
        // is already true. Measured here rather than reasoned about.
        $hooks = GateHookInspector::before($this->containerGate());

        self::assertContains(self::SPATIE_HOOK, $hooks);
        self::assertContains(self::BOUNCER_HOOK, $hooks);
    }

    #[Test]
    public function a_hook_registered_by_a_later_provider_lands_last_under_either_order(): void
    {
        // This is the measurement 5b's design turns on. A provider booting
        // after both packages — the default position for anything a host
        // installs alongside them — gets the LAST slot in registration order,
        // which is the one slot a grant from either package short-circuits.
        $hooks = GateHookInspector::before($this->containerGate());

        self::assertSame(ProbeGateHookServiceProvider::class, end($hooks));
    }

    #[Test]
    public function an_earlier_grant_short_circuits_a_later_deny_only_hook(): void
    {
        $denyHookReached = false;

        $gate = $this->bareGate();
        $gate->before(fn (): bool => true);
        $gate->before(function () use (&$denyHookReached): bool {
            $denyHookReached = true;

            return false;
        });

        self::assertTrue($gate->allows('any.ability'));
        self::assertFalse($denyHookReached, 'a deny-only before hook is never even reached behind a grant');
    }

    #[Test]
    public function an_after_hook_cannot_overturn_an_earlier_grant(): void
    {
        $afterHookReached = false;

        $gate = $this->bareGate();
        $gate->before(fn (): bool => true);
        $gate->after(function () use (&$afterHookReached): bool {
            $afterHookReached = true;

            return false;
        });

        self::assertTrue($gate->allows('any.ability'));
        self::assertTrue($afterHookReached, 'the after hook does run — it simply cannot change the result');
    }

    #[Test]
    public function a_deny_only_hook_registered_first_does_hold(): void
    {
        // The mirror image, so the finding is stated as an ordering property
        // rather than a property of deny-only hooks.
        $gate = $this->bareGate();
        $gate->before(fn (): bool => false);
        $gate->before(fn (): bool => true);

        self::assertFalse($gate->allows('any.ability'));
    }

    /**
     * @return list<string>
     */
    abstract protected function expectedBeforeHooks(): array;

    protected function containerGate(): Gate
    {
        $gate = $this->app?->make(GateContract::class);

        self::assertInstanceOf(Gate::class, $gate);

        return $gate;
    }

    private function bareGate(): Gate
    {
        $container = $this->app;
        self::assertNotNull($container);

        $user = new PlainProbeUser;

        return new Gate($container, fn (): PlainProbeUser => $user);
    }
}
