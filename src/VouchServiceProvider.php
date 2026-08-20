<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Fissible\Vouch\Attempts\DatabaseAttemptStore;
use Fissible\Vouch\Console\VouchDispatchOtpOutboxCommand;
use Fissible\Vouch\Console\VouchPruneCommand;
use Fissible\Vouch\Console\VouchThrottleReportCommand;
use Fissible\Vouch\Console\VouchSmsIdentifierAuditCommand;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\ChallengeIssuer;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\SmsOtpFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Notifications\OtpChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxDelivery;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Delivery\SmsCountryNormalizer;
use Fissible\Vouch\Delivery\SmsIdentifierAudit;
use Fissible\Vouch\Delivery\UnconfiguredDeliveryEconomics;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Support\SystemClock;
use Fissible\Vouch\Tenancy\NullTenantResolver;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Fissible\Vouch\Throttle\IpCanonicalizer;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Throttle\ThrottleKey;
use Fissible\Vouch\Throttle\ThrottleReporter;
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
        $this->app->bind(DeliveryEconomics::class, UnconfiguredDeliveryEconomics::class);

        $this->app->singleton(
            OtpQueueDispatcher::class,
            fn ($app): OtpQueueDispatcher => new OtpQueueDispatcher(
                $app->make(\Illuminate\Contracts\Queue\Factory::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
                is_string(config('vouch.otp.queue_connection'))
                    ? config('vouch.otp.queue_connection')
                    : null,
                config()->string('vouch.otp.queue'),
            ),
        );

        $this->app->singleton(
            OtpChallengeOutbox::class,
            fn ($app): OtpChallengeOutbox => new OtpChallengeOutbox(
                $app['db']->connection(),
                $app->make(OtpQueueDispatcher::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
            ),
        );

        $this->app->bind(
            OtpOutboxDelivery::class,
            fn ($app): OtpOutboxDelivery => new OtpOutboxDelivery(
                $app->make(OtpDelivery::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
            ),
        );

        $this->app->singleton(
            AttemptStore::class,
            fn ($app): DatabaseAttemptStore => new DatabaseAttemptStore(
                $app['db']->connection(),
                new TransitionRules(),
            ),
        );

        $this->app->singleton(
            BoundedLockWait::class,
            fn ($app): BoundedLockWait => new BoundedLockWait($app['db']->connection()),
        );

        $this->app->singleton(LockContention::class);

        $this->app->singleton(
            ThrottleConfiguration::class,
            static fn (): ThrottleConfiguration => ThrottleConfiguration::from(
                config('vouch.throttle'),
                config('vouch.otp.length'),
                config('vouch.totp.digits'),
                config('vouch.totp.window'),
            ),
        );

        $this->app->singleton(IdentifierCanonicalizer::class);
        $this->app->singleton(IpCanonicalizer::class);
        $this->app->singleton(ThrottleKey::class);
        $this->app->singleton(SmsCountryNormalizer::class, static fn (): SmsCountryNormalizer => SmsCountryNormalizer::defaults());
        $this->app->singleton(
            SmsIdentifierAudit::class,
            static fn ($app): SmsIdentifierAudit => new SmsIdentifierAudit($app->make(SmsCountryNormalizer::class)),
        );

        $this->app->singleton(
            ThrottleReporter::class,
            fn ($app): ThrottleReporter => new ThrottleReporter(
                $app['db']->connection(),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
                $app->make(ThrottleConfiguration::class),
            ),
        );

        $this->app->singleton(
            AuthThrottleStore::class,
            fn ($app): DatabaseAuthThrottleStore => new DatabaseAuthThrottleStore(
                $app['db']->connection(),
                new \Fissible\Vouch\Support\DatabaseTime($app['db']->connection()),
                $app->make(ThrottleConfiguration::class),
                $app->make(BoundedLockWait::class),
                $app->make(LockContention::class),
            ),
        );

        $this->app->singleton(
            EnrollmentGuard::class,
            fn ($app): EnrollmentGuard => new EnrollmentGuard(
                $app['db']->connection(),
                // config()->integer(), not (int) config(): the latter casts
                // mixed, which PHPStan level 9 refuses to trust as safe.
                config()->integer('vouch.enrollment.lock_wait_seconds'),
                $app->make(BoundedLockWait::class),
                $app->make(LockContention::class),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Flow\ScreenBuilder::class,
            fn ($app): \Fissible\Vouch\Flow\ScreenBuilder => new \Fissible\Vouch\Flow\ScreenBuilder(
                new \Fissible\Vouch\Kernel\Enumeration\ErrorShaper(),
                $app->make(\Fissible\Vouch\Factors\FactorRegistry::class),
            ),
        );

        $this->app->singleton(
            ChallengeIssuer::class,
            fn ($app): ChallengeIssuer => new ChallengeIssuer(
                $app->make(AuthThrottleStore::class),
                $app->make(ThrottleKey::class),
                $app->make(FactorRegistry::class),
                $app->make(OtpDelivery::class),
                $app->make(OtpChallengeOutbox::class),
                $this->challengeFactors(),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class,
            \Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary::class,
        );

        $this->app->singleton(
            \Fissible\Vouch\Flow\AuthFlow::class,
            fn ($app): \Fissible\Vouch\Flow\AuthFlow => new \Fissible\Vouch\Flow\AuthFlow(
                $app->make(\Fissible\Vouch\Contracts\AttemptStore::class),
                $app->make(\Fissible\Vouch\Contracts\AuthThrottleStore::class),
                $app->make(\Fissible\Vouch\Throttle\ThrottleKey::class),
                $app->make(\Fissible\Vouch\Contracts\TenantResolver::class),
                $app->make(\Fissible\Vouch\Factors\FactorRegistry::class),
                $app->make(ChallengeIssuer::class),
                $app->make(\Fissible\Vouch\Flow\ScreenBuilder::class),
                new \Fissible\Vouch\Kernel\Satisfiability\SatisfiabilityEvaluator(),
                $app->make(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class),
                new \Fissible\Vouch\Flow\VerificationEqualizer(
                    $app->make(\Illuminate\Contracts\Hashing\Hasher::class),
                ),
                $app->make(\Psr\Clock\ClockInterface::class),
                config()->integer('vouch.attempts.ttl_seconds'),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Sessions\SessionLifecycle::class,
            fn ($app): \Fissible\Vouch\Sessions\SessionLifecycle => new \Fissible\Vouch\Sessions\SessionLifecycle(
                $app->make(\Illuminate\Contracts\Session\Session::class),
                $app->make(\Psr\Clock\ClockInterface::class),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Support\DatabaseTime::class,
            fn ($app): \Fissible\Vouch\Support\DatabaseTime => new \Fissible\Vouch\Support\DatabaseTime(
                $app['db']->connection(),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Recovery\GraceGuard::class,
            fn ($app): \Fissible\Vouch\Recovery\GraceGuard => new \Fissible\Vouch\Recovery\GraceGuard(
                $app['db']->connection(),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
                config()->integer('vouch.recovery_grace.ttl_seconds'),
            ),
        );

        foreach ([
            \Fissible\Vouch\Http\IntendedDestination::class,
            \Fissible\Vouch\Http\FlowResultSerializer::class,
            \Fissible\Vouch\Http\AssuranceComparator::class,
        ] as $simple) {
            $this->app->singleton($simple);
        }

        $this->app->singleton(
            \Fissible\Vouch\Http\FlowResultHandler::class,
            fn ($app): \Fissible\Vouch\Http\FlowResultHandler => new \Fissible\Vouch\Http\FlowResultHandler(
                $app->make(\Fissible\Vouch\Sessions\SessionLifecycle::class),
                $app->make(\Fissible\Vouch\Recovery\GraceGuard::class),
                $app->make(\Illuminate\Contracts\Auth\StatefulGuard::class),
                $app->make(\Illuminate\Contracts\Session\Session::class),
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

        $this->app->bind(RandomSource::class, \Fissible\Vouch\Support\SystemRandomSource::class);

        $this->app->singleton(
            RecoveryCodeFactor::class,
            fn ($app): RecoveryCodeFactor => new RecoveryCodeFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                config()->integer('vouch.recovery.count'),
                config()->integer('vouch.recovery.length'),
                $app->make(RandomSource::class),
            ),
        );

        $this->app->singleton(
            EmailOtpFactor::class,
            fn ($app): EmailOtpFactor => new EmailOtpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                $app->make(OtpChallengeOutbox::class),
                $app->make(AuthThrottleStore::class),
                config()->integer('vouch.otp.length'),
                config()->integer('vouch.otp.ttl_seconds'),
                $app->make(RandomSource::class),
            ),
        );

        $this->app->singleton(
            SmsOtpFactor::class,
            fn ($app): SmsOtpFactor => new SmsOtpFactor(
                $app->make(EnrollmentGuard::class),
                $app->make(ClockInterface::class),
                $app->make(OtpChallengeOutbox::class),
                $app->make(AuthThrottleStore::class),
                config()->integer('vouch.otp.length'),
                config()->integer('vouch.otp.ttl_seconds'),
                $app->make(RandomSource::class),
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
        // Validation is eager: an invalid security budget must fail package boot,
        // not wait for the first attacker-controlled request to reach a store.
        $this->app->make(ThrottleConfiguration::class);

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadRoutesFrom(__DIR__ . '/../routes/vouch.php');

        $router = $this->app->make(\Illuminate\Routing\Router::class);
        $router->aliasMiddleware('vouch.session', \Fissible\Vouch\Http\Middleware\ValidatesVouchSession::class);
        $router->aliasMiddleware('vouch.assurance', \Fissible\Vouch\Http\Middleware\RequireAssurance::class);
        $router->pushMiddlewareToGroup('web', \Fissible\Vouch\Http\Middleware\ValidatesVouchSession::class);

        /*
         * A runtime check is authoritative only on requests that actually
         * traverse it. Vouch controls its own code path, but not the host's
         * routes — so the middleware's PRESENCE is asserted at boot, and its
         * absence is a hard failure rather than a silently unguarded app.
         */
        if (! in_array(
            \Fissible\Vouch\Http\Middleware\ValidatesVouchSession::class,
            $router->getMiddlewareGroups()['web'] ?? [],
            true,
        )) {
            throw new \RuntimeException(
                'Vouch requires ValidatesVouchSession in the "web" middleware group. Without '
                . 'it, revoking a session sets a column nobody reads and the revoked session '
                . 'keeps working.',
            );
        }

        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/vouch.php' => $this->app->configPath('vouch.php'),
            ], 'vouch-config');

            $this->publishes([
                __DIR__ . '/../database/migrations' => $this->app->databasePath('migrations'),
            ], 'vouch-migrations');

            $this->commands([
                VouchPruneCommand::class,
                VouchDispatchOtpOutboxCommand::class,
                VouchThrottleReportCommand::class,
                VouchSmsIdentifierAuditCommand::class,
            ]);
        }
    }

    /** @return list<string> */
    private function challengeFactors(): array
    {
        $configured = config()->array('vouch.challenges.require_credential');
        $factors = [];

        foreach ($configured as $factor) {
            if (! is_string($factor)) {
                throw new \InvalidArgumentException(
                    'Configuration "vouch.challenges.require_credential" must be a list of strings.',
                );
            }

            $factors[] = $factor;
        }

        return $factors;
    }
}
