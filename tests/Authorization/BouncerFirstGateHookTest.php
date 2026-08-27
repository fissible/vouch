<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Authorization;

use Fissible\Vouch\Tests\Support\Authorization\ProbeGateHookServiceProvider;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Application;
use Silber\Bouncer\BouncerServiceProvider;
use Spatie\Permission\PermissionServiceProvider;

/**
 * Bouncer boots first, so the Gate singleton is already resolved by the time
 * spatie's provider boots. This is the order `composer.lock` produces here.
 */
final class BouncerFirstGateHookTest extends GateHookRegistrationProbeCase
{
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
            ProbeGateHookServiceProvider::class,
        ];
    }

    /**
     * @return list<string>
     */
    protected function expectedBeforeHooks(): array
    {
        return [
            'Silber\Bouncer\Guard',
            'Spatie\Permission\PermissionRegistrar',
            ProbeGateHookServiceProvider::class,
        ];
    }
}
