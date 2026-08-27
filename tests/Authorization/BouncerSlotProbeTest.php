<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Tests\Support\Authorization\GrantingClipboard;
use Fissible\Vouch\Tests\Support\Authorization\Models\PlainProbeUser;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\Test;
use Silber\Bouncer\Bouncer;
use Silber\Bouncer\BouncerServiceProvider;

/**
 * Task 5a probe 1, continued: Bouncer's hook is registered in BOTH slots, and
 * which one is live is a host switch.
 *
 * `Guard::$slot` defaults to `'after'`. Bouncer registers a `before` and an
 * `after` callback either way, but each returns early unless it is the active
 * slot — so reading the registration list alone overstates the hazard. The
 * host flips it with `Bouncer::runBeforePolicies()`.
 *
 * This matters to 5b because the two settings put a Bouncer grant on opposite
 * sides of a deny-only before hook.
 */
final class BouncerSlotProbeTest extends TestCase
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            BouncerServiceProvider::class,
            VouchServiceProvider::class,
        ];
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->make(Bouncer::class)->setClipboard(new GrantingClipboard);
    }

    #[Test]
    public function bouncer_grants_from_the_after_slot_by_default(): void
    {
        // Bouncer is fully functional out of the box — its grant simply
        // arrives in the after slot, where `$result ??= $afterResult` fills in
        // an undecided check rather than overriding a decided one.
        $gate = $this->gate();

        self::assertTrue($gate->forUser(new PlainProbeUser)->allows('any.ability'));
    }

    #[Test]
    public function in_the_default_slot_a_bouncer_grant_cannot_bypass_a_deny_only_before_hook(): void
    {
        $denyHookReached = false;

        $gate = $this->gate();
        $gate->before(function () use (&$denyHookReached): bool {
            $denyHookReached = true;

            return false;
        });

        self::assertFalse($gate->forUser(new PlainProbeUser)->allows('any.ability'));
        self::assertTrue($denyHookReached);
    }

    #[Test]
    public function once_the_host_calls_run_before_policies_the_grant_wins(): void
    {
        $this->bouncer()->runBeforePolicies();

        $denyHookReached = false;

        $gate = $this->gate();
        $gate->before(function () use (&$denyHookReached): bool {
            $denyHookReached = true;

            return false;
        });

        self::assertTrue($gate->forUser(new PlainProbeUser)->allows('any.ability'));
        self::assertFalse($denyHookReached, 'Bouncer registered its before hook first, so it short-circuits');
    }

    private function bouncer(): Bouncer
    {
        $bouncer = $this->app?->make(Bouncer::class);

        self::assertInstanceOf(Bouncer::class, $bouncer);

        return $bouncer;
    }

    private function gate(): GateContract
    {
        $gate = $this->app?->make(GateContract::class);

        self::assertInstanceOf(GateContract::class, $gate);

        return $gate;
    }
}
