<?php

declare(strict_types=1);

use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Http\AssuranceComparator;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * The return-target validator is the package's open-redirect boundary, and its
 * rejection arms were the densest cluster of survivors in src/Http.
 *
 * Every case below is a real bypass technique rather than an invented one. A
 * validator is defined by what it REFUSES, so the refusals are enumerated
 * individually -- a single "it rejects bad input" test proves only that one
 * technique is caught, and an attacker only needs the one that is not.
 */

/** Round-trips a candidate through the real remember/consume pair. */
function sanitized(string $candidate): ?string
{
    $store = app('session.store');
    $store->start();

    $destination = new IntendedDestination($store);
    $destination->remember($candidate);

    return $destination->consume();
}

it('accepts an ordinary origin-form path', function (string $candidate, string $expected): void {
    expect(sanitized($candidate))->toBe($expected);
})->with([
    'plain path' => ['/dashboard', '/dashboard'],
    'nested path' => ['/admin/reports/7', '/admin/reports/7'],
    'path with query' => ['/search?q=ada', '/search?q=ada'],
]);

it('refuses anything that could leave this origin', function (string $candidate): void {
    /*
     * Each of these is a documented redirect bypass:
     *
     * - `//evil.test` and `///evil.test` are protocol-relative URLs; a browser
     *   reads them as absolute and leaves the site.
     * - an explicit scheme or host is not origin-form at all.
     * - `\` is treated as `/` by several browsers, so `/\evil.test` becomes
     *   protocol-relative once normalised.
     * - the percent-encoded forms exist to survive a naive prefix check and be
     *   decoded afterwards.
     * - a bare relative path has no leading slash and would resolve against
     *   whatever the current directory happens to be.
     */
    expect(sanitized($candidate))->toBeNull();
})->with([
    'protocol-relative' => ['//evil.test/steal'],
    'triple slash' => ['///evil.test/steal'],
    'absolute https' => ['https://evil.test/steal'],
    'scheme only' => ['http://evil.test'],
    'backslash escape' => ['/\\evil.test'],
    'encoded slash' => ['/%2fevil.test'],
    'encoded backslash' => ['/%5cevil.test'],
    'uppercase encoded slash' => ['/%2Fevil.test'],
    'credentials in authority' => ['https://user:pass@evil.test/'],
    'no leading slash' => ['dashboard'],
    'empty' => [''],
]);

it('never treats a revoked or grace session as sufficient assurance', function (): void {
    /*
     * Two fail-closed arms on the same method. A revoked session is one the host
     * has already invalidated; a grace session is a constrained recovery
     * capability that must never satisfy an assurance requirement, which is the
     * whole distinction recovery grace exists to draw.
     */
    $comparator = app(AssuranceComparator::class);

    $revoked = new AuthSession(['acr' => 'aal2', 'revoked_at' => now()]);
    $grace = new AuthSession(['acr' => 'aal2', 'recovery_grace_expires_at' => now()->addMinutes(15)]);

    expect($comparator->isSufficient(null, 'aal1'))->toBeFalse()
        ->and($comparator->isSufficient($revoked, 'aal1'))->toBeFalse()
        ->and($comparator->isSufficient($grace, 'aal1'))->toBeFalse();
});

it('refuses an assurance level it does not recognise, in either position', function (): void {
    /*
     * array_search() returns false for an unknown level, and false is not a
     * position -- comparing it numerically would make an unrecognised acr look
     * weaker or stronger than everything rather than unusable. Both directions
     * must refuse: an unknown stored acr and an unknown requirement.
     */
    $comparator = app(AssuranceComparator::class);

    $unknownHeld = new AuthSession(['acr' => 'aal9', 'user_id' => 7]);
    $known = new AuthSession(['acr' => 'aal2', 'user_id' => 7]);

    expect($comparator->isSufficient($unknownHeld, 'aal1'))->toBeFalse()
        ->and($comparator->isSufficient($known, 'aal9'))->toBeFalse()
        // And the ordering itself still works.
        ->and($comparator->isSufficient($known, 'aal1'))->toBeTrue()
        ->and($comparator->isSufficient($known, 'aal3'))->toBeFalse();
});
