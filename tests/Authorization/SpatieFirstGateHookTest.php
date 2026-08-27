<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Tests\Support\Authorization\ProbeGateHookServiceProvider;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Application;
use Silber\Bouncer\BouncerServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Spatie boots first, so its `afterResolving` callback is registered against
 * an unresolved Gate and fires when Bouncer resolves it.
 */
final class SpatieFirstGateHookTest extends GateHookRegistrationProbeCase
{
    /**
     * @param  Application  $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            PermissionServiceProvider::class,
            BouncerServiceProvider::class,
            VouchServiceProvider::class,
            ProbeGateHookServiceProvider::class,
        ];
    }

    /**
     * @return list<string>
     */
    protected function expectedBeforeHooks(): array
    {
        return [
            'Spatie\Permission\PermissionRegistrar',
            'Silber\Bouncer\Guard',
            ProbeGateHookServiceProvider::class,
        ];
    }
}
