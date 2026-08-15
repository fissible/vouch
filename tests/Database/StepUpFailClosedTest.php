<?php

declare(strict_types=1);

use Fissible\Vouch\Vouch;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;

uses(RefreshDatabase::class);

/*
 * Vouch::stepUp() is the package's public API for demanding higher assurance,
 * and it fails closed on the same condition as RequireAssurance.
 *
 * The empty string is the case that matters: a missing key is obviously
 * unconfigured, but a set-but-blank VOUCH_STEP_UP_PRESENTATION_URL= reads as ''
 * and LOOKS configured. Accepting it would redirect a user who needs to step up
 * to '' -- back where they started, in a loop, with the protected route still
 * refusing.
 */

it('refuses to build a step-up redirect with no destination configured', function (mixed $configured): void {
    config(['vouch.step_up.presentation_url' => $configured]);

    $request = Request::create('/admin');
    $request->setLaravelSession(app('session.store'));

    // The MESSAGE, not just the class: RuntimeException is broad enough that a
    // missing table or an unbound service would satisfy a class-only assertion.
    // That trap cost a vacuous middleware test earlier in this audit.
    expect(fn (): mixed => Vouch::stepUp('aal2', $request))
        ->toThrow(RuntimeException::class, 'requires vouch.step_up.presentation_url to be');
})->with([
    'absent' => [null],
    'set but blank' => [''],
    'not a string' => [42],
]);

it('names the level it was asked for', function (): void {
    /*
     * The one part of that message carrying a runtime value. It is still
     * developer-facing prose -- nothing reads it -- but the interpolated level is
     * what tells an operator WHICH call site is misconfigured when several
     * routes demand different levels.
     */
    config(['vouch.step_up.presentation_url' => null]);

    $request = Request::create('/admin');
    $request->setLaravelSession(app('session.store'));

    expect(fn (): mixed => Vouch::stepUp('aal3', $request))
        ->toThrow(RuntimeException::class, 'Vouch::stepUp(aal3)');
});
