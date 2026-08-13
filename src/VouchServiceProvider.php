<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Fissible\Vouch\Attempts\DatabaseAttemptStore;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Console\VouchPruneCommand;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Support\SystemClock;
use Fissible\Vouch\Tenancy\NullTenantResolver;
use Illuminate\Support\ServiceProvider;
use Psr\Clock\ClockInterface;

final class VouchServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/vouch.php', 'vouch');

        $this->app->bind(TenantResolver::class, NullTenantResolver::class);

        $this->app->singleton(ClockInterface::class, SystemClock::class);

        /*
         * Unconfigured by default, and it THROWS. A no-op would turn "OTP is not
         * wired up" into "codes silently never arrive", and a log-writing default
         * would put a live authentication code into the one file everybody greps.
         */
        $this->app->bind(OtpDelivery::class, UnconfiguredOtpDelivery::class);

        $this->app->singleton(
            AttemptStore::class,
            fn ($app): DatabaseAttemptStore => new DatabaseAttemptStore(
                $app['db']->connection(),
                new TransitionRules(),
            ),
        );

        $this->app->singleton(
            EnrollmentGuard::class,
            fn ($app): EnrollmentGuard => new EnrollmentGuard(
                $app['db']->connection(),
                // config()->integer(), not (int) config(): the latter casts
                // mixed, which PHPStan level 9 refuses to trust as safe.
                config()->integer('vouch.enrollment.lock_wait_seconds'),
            ),
        );

        $this->registerFactorDrivers();

        /*
         * AuditSink is deliberately left unbound. Its drivers ship in Phase 2.4;
         * a host resolving it before then should get a clear container error
         * rather than a silent no-op that discards audit events.
         */
    }

    /**
     * The five drivers of Phase 2.2, plus the registry that resolves them.
     *
     * Passkey is absent on purpose — sub-project 2.2b, gated on evaluating
     * laravel/passkeys, which is pre-1.0.
     */
    private function registerFactorDrivers(): void
    {
        $this->app->singleton(
            PasswordFactor::class,
            fn ($app): PasswordFactor => new PasswordFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
            ),
        );

        $this->app->singleton(
            TotpFactor::class,
            fn ($app): TotpFactor => new TotpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                config()->string('vouch.totp.issuer'),
                config()->integer('vouch.totp.period'),
                config()->integer('vouch.totp.digits'),
                config()->integer('vouch.totp.window'),
            ),
        );

        $this->app->singleton(
            RecoveryCodeFactor::class,
            fn ($app): RecoveryCodeFactor => new RecoveryCodeFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                config()->integer('vouch.recovery.count'),
                config()->integer('vouch.recovery.length'),
            ),
        );

        $this->app->singleton(
            EmailOtpFactor::class,
            fn ($app): EmailOtpFactor => new EmailOtpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                $app->make(OtpDelivery::class),
                config()->integer('vouch.otp.length'),
                config()->integer('vouch.otp.ttl_seconds'),
            ),
        );

        $this->app->singleton(
            SmsOtpFactor::class,
            fn ($app): SmsOtpFactor => new SmsOtpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                $app->make(OtpDelivery::class),
                config()->integer('vouch.otp.length'),
                config()->integer('vouch.otp.ttl_seconds'),
            ),
        );

        $this->app->singleton(FactorRegistry::class, function ($app): FactorRegistry {
            $registry = new FactorRegistry();

            foreach ([
                PasswordFactor::class,
                TotpFactor::class,
                EmailOtpFactor::class,
                SmsOtpFactor::class,
                RecoveryCodeFactor::class,
            ] as $driver) {
                $registry->register($app->make($driver));
            }

            return $registry;
        });
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
