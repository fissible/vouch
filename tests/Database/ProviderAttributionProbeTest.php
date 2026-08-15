<?php

declare(strict_types=1);

use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Routing\RouteCollection;
use Illuminate\Routing\Router;

uses(RefreshDatabase::class);

/*
 * DISPOSABLE PROBE. Not a ruling.
 *
 * The question is narrow: are the provider's boot() lines attributable to a test
 * at all, or only unattributable during Testbench's bootstrap? If invoking boot()
 * inside a test body makes the mutation observable, the rows are ordinary kills
 * and there is no fourth category.
 *
 * The router's route collection is emptied first, so the assertion cannot pass on
 * routes the real bootstrap already registered -- otherwise this would be
 * vacuous, which is the failure mode this whole audit exists to catch.
 */

it('registers its routes when boot() is invoked from a test body', function (): void {
    $router = app(Router::class);
    $router->setRoutes(new RouteCollection());

    expect($router->getRoutes()->getRoutes())->toBeEmpty();

    (new VouchServiceProvider(app()))->boot();

    $uris = array_map(
        static fn (\Illuminate\Routing\Route $route): string => $route->uri(),
        $router->getRoutes()->getRoutes(),
    );

    expect($uris)->toContain('vouch/auth');
});
