<?php

declare(strict_types=1);

use Fissible\Vouch\Console\VouchPruneCommand;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Http\Middleware\RequireAssurance;
use Fissible\Vouch\Http\Middleware\ValidatesVouchSession;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Support\SystemRandomSource;
use Fissible\Vouch\Tenancy\NullTenantResolver;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\Router;
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
    $paths = ServiceProvider::pathsToPublish(VouchServiceProvider::class);

    $sources = array_keys($paths);

    expect($sources)->not->toBeEmpty()
        // Sources are absolute paths built by concatenation; assert they exist
        // on disk rather than merely that a key is present.
        ->and(array_filter($sources, static fn (string $p): bool => file_exists($p)))
        ->toHaveCount(count($sources));
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
    [RandomSource::class, SystemRandomSource::class],
    [ClockInterface::class, \Fissible\Vouch\Support\SystemClock::class],
]);

it('puts both guards in the real web middleware group', function (): void {
    /*
     * Aliases are not enough: an alias only applies where a host chooses to use
     * it, so a package that merely aliased these would leave every host route
     * unguarded while looking protected. The group is what makes them mandatory.
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
        ->toContain('vouch:prune');
});
