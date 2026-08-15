<?php

declare(strict_types=1);

/*
 * Proves the bootstrap raise is scoped to mutation children.
 *
 * The ordinary suite must stay at the pinned 128M, because
 * SatisfiabilityEvaluatorTest's wide-policy guard only observes the
 * eager-materialisation regression as a failure when that limit is in force.
 * A convenience raise would leave it reporting green while no longer guarding.
 */

it('runs the ordinary suite at the pinned limit', function (): void {
    // Reads the bootstrap's own constant rather than re-deriving the predicate.
    // Re-deriving it is what made this test fail the first full-scope run: it
    // checked PEST_MUTATION_TESTING only, which the ORCHESTRATOR does not carry.
    $expected = \Fissible\Vouch\Tests\Support\MutationRun::isActive() ? '4G' : '128M';

    expect(ini_get('memory_limit'))->toBe($expected);
});
