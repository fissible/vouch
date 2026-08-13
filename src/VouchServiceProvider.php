<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Fissible\Vouch\Attempts\DatabaseAttemptStore;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Console\VouchPruneCommand;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Tenancy\NullTenantResolver;
use Illuminate\Support\ServiceProvider;

final class VouchServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/vouch.php', 'vouch');

        $this->app->bind(TenantResolver::class, NullTenantResolver::class);

        $this->app->singleton(
            AttemptStore::class,
            fn ($app): DatabaseAttemptStore => new DatabaseAttemptStore(
                $app['db']->connection(),
                new TransitionRules(),
            ),
        );

        /*
         * AuditSink is deliberately left unbound. Its drivers ship in Phase 2.4;
         * a host resolving it before then should get a clear container error
         * rather than a silent no-op that discards audit events.
         */

        $this->app->singleton(
            \Fissible\Vouch\Enrollment\EnrollmentGuard::class,
            fn ($app): \Fissible\Vouch\Enrollment\EnrollmentGuard => new \Fissible\Vouch\Enrollment\EnrollmentGuard(
                $app['db']->connection(),
                // config()->integer(), not (int) config(): the latter casts
                // mixed, which PHPStan level 9 refuses to trust as safe.
                config()->integer('vouch.enrollment.lock_wait_seconds'),
            ),
        );

        $this->app->singleton(
            \Psr\Clock\ClockInterface::class,
            \Fissible\Vouch\Support\SystemClock::class,
        );

        $this->app->singleton(
            \Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class,
            fn ($app): \Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor => new \Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor(
                $app->make(\Fissible\Vouch\Enrollment\EnrollmentGuard::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                config()->integer('vouch.recovery.count'),
                config()->integer('vouch.recovery.length'),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Factors\Drivers\TotpFactor::class,
            fn ($app): \Fissible\Vouch\Factors\Drivers\TotpFactor => new \Fissible\Vouch\Factors\Drivers\TotpFactor(
                $app->make(\Fissible\Vouch\Enrollment\EnrollmentGuard::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                config()->string('vouch.totp.issuer'),
                config()->integer('vouch.totp.period'),
                config()->integer('vouch.totp.digits'),
                config()->integer('vouch.totp.window'),
            ),
        );

        $this->app->bind(
            \Fissible\Vouch\Contracts\OtpDelivery::class,
            \Fissible\Vouch\Notifications\UnconfiguredOtpDelivery::class,
        );

        foreach ([
            \Fissible\Vouch\Factors\Drivers\EmailOtpFactor::class,
            \Fissible\Vouch\Factors\Drivers\SmsOtpFactor::class,
        ] as $driver) {
            $this->app->singleton($driver, fn ($app) => new $driver(
                $app->make(\Fissible\Vouch\Enrollment\EnrollmentGuard::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                $app->make(\Fissible\Vouch\Contracts\OtpDelivery::class),
                config()->integer('vouch.otp.length'),
                config()->integer('vouch.otp.ttl_seconds'),
            ));
        }
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

            $this->commands([
                VouchPruneCommand::class,
            ]);
        }
    }
}
