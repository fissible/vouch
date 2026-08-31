<?php

declare(strict_types=1);

use Fissible\Vouch\Http\IntendedDestination;
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

/*
 * Four AssuranceComparator::isSufficient() tests stood here — revoked/grace
 * refusal, unknown levels in either position, and the full ordering matrix.
 * They were squatting in a file about open redirects, and 2.4 Task 2a removes
 * the method they exercised: authorization now re-derives the level from the
 * persisted proof instead of comparing a stored acr string.
 *
 * The properties they protected were re-expressed, not dropped:
 *
 *   - revoked, grace and absent sessions -> tests/Assurance/SessionEvidenceTest
 *   - unknown requirement level          -> AssuranceComparisonTest, requirement parsing
 *   - unknown HELD level                 -> unrepresentable now; asserted as such
 *   - the full ordering matrix           -> AssuranceComparisonTest, the lattice group
 */
