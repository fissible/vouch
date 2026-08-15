<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

/**
 * Is this process part of a mutation run?
 *
 * The single statement of that rule. Two processes qualify, and separating them
 * cost several diagnostic attempts:
 *
 *  - mutant CHILDREN, which pest-plugin-mutate flags with PEST_MUTATION_TESTING;
 *  - the ORCHESTRATOR, which carries no such variable because it is not itself a
 *    mutant, and is recognised by its own --mutate invocation.
 *
 * A method rather than a constant so static analysis can see it, and one method
 * rather than a copy in the bootstrap and another in the test: the first version
 * restated the predicate in both places, they drifted the moment the orchestrator
 * case was added, and the test failed a full-scope run.
 */
final class MutationRun
{
    public static function isActive(): bool
    {
        if (getenv('PEST_MUTATION_TESTING') !== false) {
            return true;
        }

        /** @var list<mixed> $argv */
        $argv = $_SERVER['argv'] ?? [];

        foreach ($argv as $argument) {
            if (is_string($argument) && str_starts_with($argument, '--mutate')) {
                return true;
            }
        }

        return false;
    }
}
