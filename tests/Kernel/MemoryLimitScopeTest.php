<?php

declare(strict_types=1);

/*
 * Proves the bootstrap raise is scoped to mutation processes.
 *
 * What this asserts is the SCOPING, not the value. The ordinary suite gets whatever
 * phpunit.xml.dist declares and the mutation campaign gets 4G, and the point is that
 * those are different -- a convenience raise applied to everything would go unnoticed.
 *
 * It used to assert the ordinary value literally, as 128M, because
 * SatisfiabilityEvaluatorTest's wide-policy guard observed its regression only as
 * memory exhaustion and was calibrated against exactly that limit. That coupling is
 * gone: the guard now runs in a subprocess under a limit it sets itself, so the
 * suite's limit is free to change and this test should not fail when it does. It
 * reads the declared value instead, which is what keeps it about scoping.
 */
it('runs the ordinary suite at the declared limit, and only mutation runs higher', function (): void {
    $declared = declaredMemoryLimit();

    // Read from the bootstrap's own predicate rather than re-derived. Re-deriving it
    // is what made this test fail its first full-scope run: it checked
    // PEST_MUTATION_TESTING only, which the mutation ORCHESTRATOR does not carry.
    $expected = \Fissible\Vouch\Tests\Support\MutationRun::isActive() ? '4G' : $declared;

    expect(ini_get('memory_limit'))->toBe($expected);

    /*
     * And the two are genuinely different, so that "scoped" means something. If the
     * declared limit ever became 4G this test would otherwise pass while proving
     * nothing about scoping at all.
     */
    expect($declared)->not->toBe('4G');
});

/** The limit phpunit.xml.dist declares, read from the file rather than assumed. */
function declaredMemoryLimit(): string
{
    $configuration = file_get_contents(dirname(__DIR__, 2) . '/phpunit.xml.dist');

    if ($configuration === false) {
        throw new RuntimeException('phpunit.xml.dist is unreadable.');
    }

    if (preg_match('/<ini name="memory_limit" value="([^"]+)"\s*\/>/', $configuration, $matches) !== 1) {
        throw new RuntimeException('phpunit.xml.dist declares no memory_limit.');
    }

    return $matches[1];
}
