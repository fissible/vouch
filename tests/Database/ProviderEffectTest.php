<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Http\Middleware\RequireAssurance;
use Fissible\Vouch\Http\Middleware\ValidatesVouchSession;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Support\SystemRandomSource;
use Fissible\Vouch\Tenancy\NullTenantResolver;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\ServiceProvider;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

/*
 * The provider's OBSERVABLE package effects, asserted one by one.
 *
 * "The provider boots" proves nothing: every registration here can be deleted
 * individually and the provider still boots. What changes is which controls
 * exist at runtime -- and a host discovers that at its first request, not in this
 * repository's suite.
 *
 * The path concatenations are the sharpest case. `__DIR__ . '/../routes/vouch.php'`
 * is a filesystem path, not a message; broken, the package silently ships no
 * routes at all.
 */

it('merges package config from its own path', function (): void {
    // A value only this package's config file defines. Absent, mergeConfigFrom
    // never ran or ran against the wrong path.
    expect(config('vouch.sessions.revocation_retention_days'))->toBe(30)
        ->and(config('vouch.otp.length'))->not->toBeNull();
});

it('validates throttle configuration eagerly during provider boot', function (): void {
    // resolved() is checked before this test asks for the object. Without the
    // boot-time make(), the singleton would remain dormant until the first
    // attacker-controlled request reached throttling.
    expect(app()->resolved(ThrottleConfiguration::class))->toBeTrue();
});

it('fails boot when shared-throttle CAPTCHA escalation has no verifier', function (): void {
    Config::set('vouch.throttle.captcha.enabled', true);
    Config::set('vouch.throttle.global.mode', 'enforce');
    Config::set('vouch.throttle.global.enforce_at', 10);
    Config::set('vouch.throttle.global.backoff_seconds', 1);
    app()->forgetInstance(ThrottleConfiguration::class);

    try {
        expect(fn () => (new VouchServiceProvider(app()))->boot())
            ->toThrow(RuntimeException::class, 'CAPTCHA escalation is enabled');
    } finally {
        Config::set('vouch.throttle.captcha.enabled', false);
        Config::set('vouch.throttle.global.mode', 'observe');
        Config::set('vouch.throttle.global.enforce_at', null);
        Config::set('vouch.throttle.global.backoff_seconds', null);
        app()->forgetInstance(ThrottleConfiguration::class);
    }
});

it('fails boot when the host does not retain the session validator in web', function (): void {
    $originalRouter = app(Router::class);
    $originalArgv = $_SERVER['argv'] ?? null;

    // Keep this command outside the CAPTCHA exemption so the test reaches the
    // middleware-group guard rather than depending on the doctor boot path.
    $_SERVER['argv'] = ['artisan', 'about'];
    $router = new class(app('events'), app()) extends Router {
        public function pushMiddlewareToGroup($group, $middleware)
        {
            // Simulate a host that silently ignores the package's push.
            return $this;
        }

        /** @return array<string, list<string>> */
        public function getMiddlewareGroups()
        {
            return ['web' => []];
        }
    };

    Facade::clearResolvedInstance('router');
    app()->instance(Router::class, $router);

    try {
        expect(fn () => (new VouchServiceProvider(app()))->boot())
            ->toThrow(
                RuntimeException::class,
                'Vouch requires ValidatesVouchSession in the "web" middleware group. Without '
                . 'it, revoking a session sets a column nobody reads and the revoked session '
                . 'keeps working.',
            );
    } finally {
        app()->instance(Router::class, $originalRouter);
        Facade::clearResolvedInstance('router');

        if ($originalArgv === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $originalArgv;
        }
    }
});

it('fails provider boot on a set-but-blank throttle value', function (): void {
    Config::set('vouch.throttle.window_seconds', '');
    app()->forgetInstance(ThrottleConfiguration::class);

    (new VouchServiceProvider(app()))->boot();
})->throws(
    InvalidArgumentException::class,
    'Configuration "vouch.throttle.window_seconds" must be a positive integer; got an empty string.',
);

it('loads migrations from its own path', function (): void {
    // RefreshDatabase runs whatever loadMigrationsFrom registered.
    expect(Schema::hasTable('auth_attempts'))->toBeTrue()
        ->and(Schema::hasTable('auth_sessions'))->toBeTrue()
        ->and(Schema::hasTable('auth_credentials'))->toBeTrue();
});

it('loads routes from its own path', function (): void {
    // The flow endpoint must actually exist. A broken route path leaves the
    // package installed and unreachable.
    $uris = array_map(
        static fn (\Illuminate\Routing\Route $route): string => $route->uri(),
        app(Router::class)->getRoutes()->getRoutes(),
    );

    expect($uris)->toContain('vouch/auth');
});

it('publishes its config and migrations from the intended paths', function (): void {
    /*
     * Asserted per tag, as exact source-to-target pairs.
     *
     * The previous version asked only that the source list was non-empty and
     * that every entry existed on disk, and the mutation gate showed both halves
     * to be too weak to see anything:
     *
     *  - Non-empty survives DELETING either publishes() call outright, because
     *     the other one keeps the list non-empty. Same for emptying either
     *     array. That is the standing rule about never asserting membership of a
     *     list that contains all the candidates.
     *  - file_exists() survives truncating `__DIR__ . '/../config/vouch.php'`
     *     down to `__DIR__`, because a directory exists just as happily as the
     *     file inside it. An assertion that cannot tell a path from its own
     *     parent cannot tell a correct path from a wrong one.
     *
     * Resolving both sides means a truncated concatenation fails on the value,
     * and a missing publishes() call fails on the tag.
     */
    $config = ServiceProvider::pathsToPublish(VouchServiceProvider::class, 'vouch-config');
    $migrations = ServiceProvider::pathsToPublish(VouchServiceProvider::class, 'vouch-migrations');

    // Exactly one mapping per tag: a deleted publishes() call, or an emptied
    // array, leaves the tag with nothing and fails here rather than hiding
    // behind the other tag's entries.
    expect($config)->toHaveCount(1)
        ->and($migrations)->toHaveCount(1);

    /*
     * Sources are compared through realpath because the provider builds them by
     * concatenation and they arrive unresolved, as `.../src/../config/vouch.php`.
     * Normalising both sides compares the file each path actually names.
     */
    expect(realpath((string) array_key_first($config)))
        ->toBe(realpath(__DIR__ . '/../../config/vouch.php'))
        ->and(realpath((string) array_key_first($migrations)))
        ->toBe(realpath(__DIR__ . '/../../database/migrations'));

    expect(array_values($config))->toBe([config_path('vouch.php')])
        ->and(array_values($migrations))->toBe([database_path('migrations')]);

    // The sources are what gets copied; a directory standing in for a file is
    // exactly the shape a truncated concatenation produces.
    expect(is_file((string) array_key_first($config)))->toBeTrue()
        ->and(is_dir((string) array_key_first($migrations)))->toBeTrue();
});

it('binds every contract to its intended implementation', function (string $contract, string $implementation): void {
    // A real check rather than a cast: the dataset supplies plain strings, and
    // asserting they name loadable classes is part of what this proves.
    if (! class_exists($implementation) && ! interface_exists($implementation)) {
        throw new RuntimeException('Not a resolvable class: ' . $implementation);
    }

    expect(app($contract))->toBeInstanceOf($implementation);
})->with([
    [TenantResolver::class, NullTenantResolver::class],
    [OtpDelivery::class, UnconfiguredOtpDelivery::class],
    [AuthThrottleStore::class, DatabaseAuthThrottleStore::class],
    [RandomSource::class, SystemRandomSource::class],
    [ClockInterface::class, \Fissible\Vouch\Support\SystemClock::class],
]);

it('explicitly binds every 2.3b service even when Laravel could autowire it', function (string $service): void {
    /*
     * Resolving a concrete class is not evidence that the provider registered
     * it: Laravel will autowire most of these after a dropped binding. bound()
     * distinguishes the package contract from container convenience.
     */
    expect(app()->bound($service))->toBeTrue();
})->with([
    \Fissible\Vouch\Contracts\AuthThrottleStore::class,
    \Fissible\Vouch\Factors\ChallengeIssuer::class,
    \Fissible\Vouch\Notifications\OtpChallengeOutbox::class,
    \Fissible\Vouch\Notifications\OtpOutboxDelivery::class,
    \Fissible\Vouch\Notifications\OtpQueueDispatcher::class,
    \Fissible\Vouch\Support\BoundedLockWait::class,
    \Fissible\Vouch\Support\DatabaseTime::class,
    \Fissible\Vouch\Support\LockContention::class,
    \Fissible\Vouch\Throttle\IdentifierCanonicalizer::class,
    \Fissible\Vouch\Throttle\IpCanonicalizer::class,
    \Fissible\Vouch\Throttle\ThrottleConfiguration::class,
    \Fissible\Vouch\Throttle\ThrottleKey::class,
    \Fissible\Vouch\Throttle\ThrottleReporter::class,
]);

it('puts the session validator in the real web middleware group', function (): void {
    /*
     * An alias is not enough for session revocation: it would apply only where a
     * host chose it, leaving authenticated routes unguarded. RequireAssurance is
     * different and deliberately route-scoped because each use supplies its
     * required assurance level; its exact alias is asserted separately below.
     */
    $web = app(Router::class)->getMiddlewareGroups()['web'] ?? [];

    expect($web)->toContain(ValidatesVouchSession::class);
});

it('registers both middleware aliases as well', function (): void {
    $aliases = app(Router::class)->getMiddleware();

    expect($aliases)->toHaveKey('vouch.session')
        ->and($aliases)->toHaveKey('vouch.assurance')
        ->and($aliases['vouch.session'])->toBe(ValidatesVouchSession::class)
        ->and($aliases['vouch.assurance'])->toBe(RequireAssurance::class);
});

it('registers its console command', function (): void {
    expect(array_keys(app(\Illuminate\Contracts\Console\Kernel::class)->all()))
        ->toContain('vouch:prune')
        ->toContain('vouch:otp-outbox:dispatch')
        ->toContain('vouch:throttle:report');
});
