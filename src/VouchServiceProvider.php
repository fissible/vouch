<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Tenancy\NullTenantResolver;
use Illuminate\Support\ServiceProvider;

final class VouchServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/vouch.php', 'vouch');

        $this->app->bind(TenantResolver::class, NullTenantResolver::class);

        /*
         * AuditSink is deliberately left unbound. Its drivers ship in Phase 2.4;
         * a host resolving it before then should get a clear container error
         * rather than a silent no-op that discards audit events.
         */
    }

    public function boot(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/vouch.php' => $this->app->configPath('vouch.php'),
            ], 'vouch-config');

            $this->publishes([
                __DIR__ . '/../database/migrations' => $this->app->databasePath('migrations'),
            ], 'vouch-migrations');
        }
    }
}
