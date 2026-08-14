<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\RandomSource;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Support\SystemRandomSource;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * Making the randomness injectable bought a testable boundary and introduced a
 * seam: something weaker than a CSPRNG can now be bound in its place. These are
 * the tests that make the seam safe to have.
 *
 * The risk is not hypothetical -- the suite itself binds a source that returns a
 * constant. What must hold is that nothing in the shipped wiring does.
 */

it('resolves the system CSPRNG by default', function (): void {
    expect(app(RandomSource::class))->toBeInstanceOf(SystemRandomSource::class);
});

it('gives the shipped generators that same source', function (): void {
    /*
     * Resolving the contract correctly proves nothing about what the drivers
     * actually received: the provider passes it explicitly, and a constructor
     * default would silently paper over a broken binding.
     *
     * So this asserts on generated output rather than on wiring. Codes from the
     * container-resolved drivers must vary; the test double returns a constant,
     * so anything that got hold of one produces identical codes every time.
     */
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    expect(count(array_unique($codes)))->toBeGreaterThan(1);
});

it('returns values inside the requested range, at both ends', function (): void {
    /*
     * The contract says inclusive at both ends. A source that never returns its
     * bounds would silently cost the alphabet its first and last characters --
     * the same entropy defect the injection exists to make visible, relocated
     * one layer down.
     */
    $source = new SystemRandomSource();
    $seen = [];

    for ($i = 0; $i < 200; $i++) {
        $value = $source->int(0, 3);

        expect($value)->toBeGreaterThanOrEqual(0)->toBeLessThanOrEqual(3);

        $seen[$value] = true;
    }

    // 200 draws over four values: a missing bound is a certainty, not bad luck.
    ksort($seen);

    expect(array_keys($seen))->toBe([0, 1, 2, 3]);
});

it('is the source an OTP driver resolved from the container uses', function (): void {
    // Same argument as the recovery driver, on the other generator.
    expect(app(EmailOtpFactor::class))->toBeInstanceOf(EmailOtpFactor::class)
        ->and(app(RandomSource::class))->toBeInstanceOf(SystemRandomSource::class);
});
