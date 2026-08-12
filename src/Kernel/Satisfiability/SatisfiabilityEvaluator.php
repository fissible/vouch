<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Satisfiability;

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;
use Fissible\Vouch\Kernel\Policy\Requirement;

final class SatisfiabilityEvaluator
{
    /**
     * @param list<SatisfiedFactor> $satisfied
     */
    public function evaluate(Requirement $requirement, array $satisfied): Verdict
    {
        // Recovery grants a restricted recovery-grace session (spec §7.3); it never
        // contributes to a policy. Filtered here rather than relying on strength
        // ordering, so a policy with no minimum strength still cannot accept it.
        $eligible = array_values(array_filter(
            $satisfied,
            static fn (SatisfiedFactor $factor): bool => $factor->strength !== FactorStrength::Recovery,
        ));

        $solutions = $this->solve($requirement, $eligible);

        return $solutions === []
            ? Verdict::unsatisfied()
            : Verdict::satisfiedBy($solutions[0]);
    }

    /**
     * Every distinct factor set that satisfies $requirement.
     *
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solve(Requirement $requirement, array $pool): array
    {
        return match (true) {
            $requirement instanceof FactorRequirement => $this->solveLeaf($requirement, $pool),
            $requirement instanceof AnyOf => $this->solveAnyOf($requirement, $pool),
            $requirement instanceof AllOf => $this->solveAllOf($requirement, $pool),
            default => [],
        };
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solveLeaf(FactorRequirement $requirement, array $pool): array
    {
        $solutions = [];

        foreach ($pool as $candidate) {
            if ($this->leafMatches($requirement, $candidate)) {
                $solutions[] = [$candidate];
            }
        }

        return $solutions;
    }

    private function leafMatches(FactorRequirement $requirement, SatisfiedFactor $factor): bool
    {
        if ($factor->factorId !== $requirement->factorId) {
            return false;
        }

        if ($requirement->userVerified !== null && $factor->userVerified !== $requirement->userVerified) {
            return false;
        }

        if ($requirement->phishingResistant !== null && $factor->phishingResistant !== $requirement->phishingResistant) {
            return false;
        }

        if ($requirement->minimumStrength !== null && ! $factor->strength->atLeast($requirement->minimumStrength)) {
            return false;
        }

        return true;
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solveAnyOf(AnyOf $requirement, array $pool): array
    {
        $solutions = [];

        foreach ($requirement->requirements as $child) {
            foreach ($this->solve($child, $pool) as $solution) {
                $solutions[] = $solution;
            }
        }

        return $solutions;
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @return list<list<SatisfiedFactor>>
     */
    private function solveAllOf(AllOf $requirement, array $pool): array
    {
        /** @var list<list<SatisfiedFactor>> $accumulated */
        $accumulated = [[]];

        foreach ($requirement->requirements as $child) {
            $next = [];

            foreach ($accumulated as $partial) {
                foreach ($this->solve($child, $pool) as $addition) {
                    if ($this->compatible($requirement, $partial, $addition)) {
                        $next[] = [...$partial, ...$addition];
                    }
                }
            }

            if ($next === []) {
                return [];
            }

            $accumulated = $next;
        }

        return $accumulated;
    }

    /**
     * @param list<SatisfiedFactor> $partial
     * @param list<SatisfiedFactor> $addition
     */
    private function compatible(AllOf $requirement, array $partial, array $addition): bool
    {
        foreach ($addition as $incoming) {
            foreach ($partial as $existing) {
                if ($requirement->requireDistinctCredentials
                    && $existing->credentialId === $incoming->credentialId) {
                    return false;
                }

                if ($requirement->requireIndependentAuthenticators
                    && $existing->authenticatorId !== null
                    && $existing->authenticatorId === $incoming->authenticatorId) {
                    return false;
                }
            }
        }

        return true;
    }
}
