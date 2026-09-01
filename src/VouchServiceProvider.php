<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Fissible\Vouch\Attempts\DatabaseAttemptStore;
use Fissible\Vouch\Authorization\AssuranceGateHook;
use Fissible\Vouch\Authorization\AssuranceRequirements;
use Fissible\Vouch\Authorization\RouteAbilityScanner;
use Fissible\Vouch\Console\VouchAssuranceMapCommand;
use Fissible\Vouch\Console\VouchDispatchOtpOutboxCommand;
use Fissible\Vouch\Console\VouchDoctorCommand;
use Fissible\Vouch\Console\VouchPruneCommand;
use Fissible\Vouch\Console\VouchThrottleReportCommand;
use Fissible\Vouch\Console\VouchSmsIdentifierAuditCommand;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\CaptchaVerifier;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Enrollment\FirstCredentialEnrollment;
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
use Fissible\Vouch\Verification\IdentifierVerificationOutbox;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\RecoveryProofOutbox;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Delivery\SmsCountryNormalizer;
use Fissible\Vouch\Delivery\SmsIdentifierAudit;
use Fissible\Vouch\Delivery\UnconfiguredCaptchaVerifier;
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
use Fissible\Vouch\Tokens\Drivers\SanctumTokenIssuer;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Illuminate\Support\ServiceProvider;
use Psr\Clock\ClockInterface;

final class VouchServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/vouch.php', 'vouch');

        $this->app->bind(TenantResolver::class, NullTenantResolver::class);

        $this->app->singleton(SanctumTokenIssuer::class);
        $this->app->bind(TokenIssuer::class, SanctumTokenIssuer::class);
        $this->app->singleton(
            TokenIssuerRegistry::class,
            fn ($app): TokenIssuerRegistry => new TokenIssuerRegistry([$app->make(SanctumTokenIssuer::class)]),
        );

        $this->app->singleton(ClockInterface::class, SystemClock::class);
        // Bound, not shared: test and long-running hosts may change config after boot.
        $this->app->bind(AssuranceRequirements::class, static fn (): AssuranceRequirements => AssuranceRequirements::from(config('vouch.assurance_requirements')));
        $this->app->bind(RouteAbilityScanner::class);
        $this->app->bind(AssuranceGateHook::class);

        /*
         * Unconfigured by default, and it THROWS. A no-op would turn "OTP is not
         * wired up" into "codes silently never arrive", and a log-writing default
         * would put a live authentication code into the one file everybody greps.
         */
        $this->app->bind(OtpDelivery::class, UnconfiguredOtpDelivery::class);
        $this->app->bind(DeliveryEconomics::class, UnconfiguredDeliveryEconomics::class);
        $this->app->bind(CaptchaVerifier::class, UnconfiguredCaptchaVerifier::class);

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

        $this->app->singleton(
            OtpOutboxDelivery::class,
            fn ($app): OtpOutboxDelivery => new OtpOutboxDelivery(
                $app->make(OtpDelivery::class),
                $app->make(\Fissible\Vouch\Contracts\DeliveryEconomics::class),
                $app->make(SmsCountryNormalizer::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
                [
                    'email' => config()->integer('vouch.delivery.economics.email_cost_minor'),
                    'sms' => config()->integer('vouch.delivery.economics.sms_cost_minor'),
                ],
            ),
        );

        $this->app->singleton(
            IdentifierVerificationOutbox::class,
            fn ($app): IdentifierVerificationOutbox => new IdentifierVerificationOutbox(
                $app['db']->connection(),
                $app->make(OtpQueueDispatcher::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
            ),
        );

        $this->app->bind(
            VerificationOutboxDelivery::class,
            fn ($app): VerificationOutboxDelivery => new VerificationOutboxDelivery(
                $app->make(OtpDelivery::class),
                $app->make(DeliveryEconomics::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
                config()->integer('vouch.delivery.economics.email_cost_minor'),
            ),
        );

        $this->app->singleton(
            RecoveryProofOutbox::class,
            fn ($app): RecoveryProofOutbox => new RecoveryProofOutbox(
                $app['db']->connection(),
                $app->make(OtpQueueDispatcher::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
            ),
        );

        $this->app->bind(
            RecoveryProofOutboxDelivery::class,
            fn ($app): RecoveryProofOutboxDelivery => new RecoveryProofOutboxDelivery(
                $app->make(OtpDelivery::class),
                $app->make(DeliveryEconomics::class),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
                config()->integer('vouch.delivery.economics.email_cost_minor'),
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

        $this->app->bind(
            IdentifierVerifier::class,
            fn ($app): IdentifierVerifier => new IdentifierVerifier(
                $app->make(AuthThrottleStore::class),
                $app->make(ThrottleKey::class),
                $app->make(IdentifierVerificationOutbox::class),
                $app['db']->connection(),
                $app->make(\Fissible\Vouch\Support\DatabaseTime::class),
                $app->make(ClockInterface::class),
                config()->integer('vouch.verification.ttl_seconds'),
                $app->make(RandomSource::class),
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

        $this->app->bind(
            FirstCredentialEnrollment::class,
            function ($app, array $parameters): FirstCredentialEnrollment {
                $connection = $parameters['connection'] ?? $app['db']->connection();

                return new FirstCredentialEnrollment(
                    $connection,
                    $app->make(IdentifierVerifier::class),
                    new BoundedLockWait($connection),
                    $app->make(LockContention::class),
                    config()->integer('vouch.enrollment.lock_wait_seconds'),
                );
            },
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
                $app->make(DeliveryEconomics::class),
                $app->make(OtpDelivery::class),
                $app->make(OtpChallengeOutbox::class),
                $this->challengeFactors(),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class,
            \Fissible\Vouch\Kernel\Assurance\NistAssuranceVocabulary::class,
        );

        $this->app->bind(
            \Fissible\Vouch\Assurance\EvidenceComparator::class,
            fn ($app): \Fissible\Vouch\Assurance\EvidenceComparator => new \Fissible\Vouch\Assurance\EvidenceComparator(
                $app->make(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Tokens\TokenAssuranceRecord::class,
            fn ($app): \Fissible\Vouch\Tokens\TokenAssuranceRecord => new \Fissible\Vouch\Tokens\TokenAssuranceRecord(
                $app['db']->connection(),
                $app->make(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class),
            ),
        );

        $this->app->bind(
            \Fissible\Vouch\Http\Middleware\RequireAbilityAssurance::class,
            fn ($app): \Fissible\Vouch\Http\Middleware\RequireAbilityAssurance => new \Fissible\Vouch\Http\Middleware\RequireAbilityAssurance(
                $app->make(AssuranceRequirements::class),
                $app->make(RouteAbilityScanner::class),
                $app->make(\Fissible\Vouch\Assurance\EvidenceComparator::class),
                $app->make(ClockInterface::class),
                $app->make(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class),
            ),
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
                $app->make(CaptchaVerifier::class),
                $app->make(ThrottleConfiguration::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                config()->integer('vouch.attempts.ttl_seconds'),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Sessions\SessionLifecycle::class,
            fn ($app): \Fissible\Vouch\Sessions\SessionLifecycle => new \Fissible\Vouch\Sessions\SessionLifecycle(
                $app->make(\Illuminate\Contracts\Session\Session::class),
                $app->make(\Psr\Clock\ClockInterface::class),
                $app->make(\Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class),
            ),
        );

        // Leave construction to the container so hosts can contextually supply
        // a registry for this operation; FactorRegistry itself is write-once.
        $this->app->singleton(\Fissible\Vouch\SelfService\CredentialSelfService::class);

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

        // Recovery composes PasswordFactor directly. FactorRegistry is write-once.
        $this->app->when(CredentialRecovery::class)
            ->needs(\Fissible\Vouch\Contracts\Factor::class)
            ->give(PasswordFactor::class);

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
                $app->make(\Fissible\Vouch\Sessions\SessionRebinder::class),
            ),
        );

        $this->app->singleton(
            \Fissible\Vouch\Sessions\SessionRebinder::class,
            \Fissible\Vouch\Sessions\DatabaseSessionRebinder::class,
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

        if (! $this->isDoctorCommand()
            && $this->app->make(ThrottleConfiguration::class)->captchaEnabled
            && $this->app->make(CaptchaVerifier::class) instanceof UnconfiguredCaptchaVerifier) {
            throw new \RuntimeException(
                'CAPTCHA escalation is enabled, but no CAPTCHA verifier is configured. '
                . 'Bind Fissible\\Vouch\\Contracts\\CaptchaVerifier before enabling '
                . 'shared-throttle enforcement.',
            );
        }

        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
        $this->loadSanctumMigrationsWhenInstalled();
        $this->loadRoutesFrom(__DIR__ . '/../routes/vouch.php');

        $router = $this->app->make(\Illuminate\Routing\Router::class);
        $router->aliasMiddleware('vouch.session', \Fissible\Vouch\Http\Middleware\ValidatesVouchSession::class);
        $router->aliasMiddleware('vouch.assurance', \Fissible\Vouch\Http\Middleware\RequireAssurance::class);
        $router->aliasMiddleware('vouch.ability', \Fissible\Vouch\Http\Middleware\RequireAbilityAssurance::class);
        $router->aliasMiddleware('vouch.token', \Fissible\Vouch\Http\Middleware\RejectsUnrecordedTokens::class);
        $ensureMiddlewareGroups = function (): void {
            $router = $this->app->make(\Illuminate\Routing\Router::class);
            $middlewareByGroup = [
                'web' => [
                    \Fissible\Vouch\Http\Middleware\ValidatesVouchSession::class,
                    \Fissible\Vouch\Http\Middleware\RequireAbilityAssurance::class,
                    \Fissible\Vouch\Http\Middleware\RejectsUnrecordedTokens::class,
                ],
                'api' => [
                    \Fissible\Vouch\Http\Middleware\RequireAbilityAssurance::class,
                    \Fissible\Vouch\Http\Middleware\RejectsUnrecordedTokens::class,
                ],
            ];

            foreach ($middlewareByGroup as $group => $middleware) {
                foreach ($middleware as $class) {
                    if (! in_array($class, $router->getMiddlewareGroups()[$group] ?? [], true)) {
                        $router->pushMiddlewareToGroup($group, $class);
                    }
                }
            }

            /*
             * A runtime check is authoritative only on requests that actually
             * traverse it. This presence check runs while the HTTP kernel is
             * resolved, not at provider boot, because only then has Laravel
             * synchronized the host's final middleware groups. Vouch controls
             * its own code path, but not the host's routes — absence is a hard
             * failure rather than a silently unguarded app.
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
        };

        $ensureMiddlewareGroups();

        // This mirrors probe 1 in authorization-integration-survey.md: callAfterResolving
        // runs immediately for an already-resolved service, or after the kernel constructor
        // syncs its default groups, so either host order retains Vouch's middleware.
        $this->callAfterResolving(\Illuminate\Contracts\Http\Kernel::class, function () use ($ensureMiddlewareGroups): void {
            $ensureMiddlewareGroups();
        });

        \Illuminate\Support\Facades\Gate::before(function (mixed $user, string $ability): ?bool {
            $request = request();
            $session = $this->app->make(\Illuminate\Contracts\Session\Session::class);

            // Gate also runs in workers and console commands, whose shared
            // container request is only a dummy. Attach a session only when
            // it has actually started, otherwise the hook must defer rather
            // than turn background authorization into a denial.
            if (! $request->hasSession() && $session->isStarted()) {
                // Authorization must not decorate the shared request: a later
                // Gate check in this long-lived process must see its real
                // request context, not a session manufactured for this call.
                $request = clone $request;
                $request->setLaravelSession($session);
            }

            return $this->app->make(AssuranceGateHook::class)->decide($user, $ability, $request);
        });

        if (config('vouch.assurance_strict') === true && ! $this->isDoctorCommand() && ! $this->isAssuranceMapCommand()) {
            $this->app->make(AssuranceRequirements::class)->assertDeclared(
                AssuranceRequirements::declaredFrom(config('vouch.declared_abilities')),
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
                VouchDoctorCommand::class,
                VouchAssuranceMapCommand::class,
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

    private function isDoctorCommand(): bool
    {
        $argv = $_SERVER['argv'] ?? [];

        if (! is_array($argv)) {
            return false;
        }

        foreach (array_slice($argv, 1) as $argument) {
            if (is_string($argument) && ! str_starts_with($argument, '-')) {
                return $argument === 'vouch:doctor';
            }
        }

        return false;
    }

    private function isAssuranceMapCommand(): bool
    {
        $argv = $_SERVER['argv'] ?? [];

        if (! is_array($argv)) {
            return false;
        }

        foreach (array_slice($argv, 1) as $argument) {
            if (is_string($argument) && ! str_starts_with($argument, '-')) {
                return $argument === 'vouch:assurance-map';
            }
        }

        return false;
    }

    private function loadSanctumMigrationsWhenInstalled(): void
    {
        if (! class_exists(\Laravel\Sanctum\Sanctum::class)) {
            return;
        }

        $file = (new \ReflectionClass(\Laravel\Sanctum\Sanctum::class))->getFileName();

        if ($file === false) {
            return;
        }

        /*
         * Sanctum is suggested, not required, so Vouch cannot name a vendor
         * path unconditionally. When it is installed, the token adapter needs
         * Sanctum's actual schema; omitting it leaves issuance to fail only at
         * its first write rather than at the optional-integration boundary.
         */
        $this->loadMigrationsFrom(dirname($file) . '/../database/migrations');
    }

}
