<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Authorization;

use Illuminate\Contracts\Auth\Access\Gate as GateContract;
use Illuminate\Support\ServiceProvider;

/**
 * Stands in for whatever provider Vouch's assurance map would register its
 * deny-only hook from. Registered after both authorization packages, which is
 * where a package a host installs alongside them lands by default.
 */
final class ProbeGateHookServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $this->callAfterResolving(GateContract::class, function (GateContract $gate): void {
            $gate->before(fn (): ?bool => null);
        });
    }
}
