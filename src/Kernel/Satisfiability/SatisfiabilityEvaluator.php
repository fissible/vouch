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

        // The search is depth-first and lazy: the first complete assignment wins and
        // nothing beyond it is ever built. Materialising every assignment first cost
        // 11.4 MB for 5 requirements over 10 factors and died outright at 6 over 12,
        // on the login path, as an uncatchable fatal.
        foreach ($this->solve($requirement, $eligible, [], []) as $solution) {
            return Verdict::satisfiedBy($solution);
        }

        return Verdict::unsatisfied();
    }

    /**
     * Every assignment that satisfies $requirement, lazily. Each one is the whole
     * running set of chosen factors — $chosen plus whatever this subtree consumed —
     * so a caller can hand it straight to the next requirement.
     *
     * @param list<SatisfiedFactor> $pool
     * @param list<SatisfiedFactor> $chosen
     * @param list<array{requirement: AllOf, from: int}> $scopes
     * @return iterable<list<SatisfiedFactor>>
     */
    private function solve(Requirement $requirement, array $pool, array $chosen, array $scopes): iterable
    {
        return match (true) {
            $requirement instanceof FactorRequirement => $this->solveLeaf($requirement, $pool, $chosen, $scopes),
            $requirement instanceof AnyOf => $this->solveAnyOf($requirement, $pool, $chosen, $scopes),
            $requirement instanceof AllOf => $this->solveAllOf($requirement, $pool, $chosen, $scopes),
            default => [],
        };
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @param list<SatisfiedFactor> $chosen
     * @param list<array{requirement: AllOf, from: int}> $scopes
     * @return iterable<list<SatisfiedFactor>>
     */
    private function solveLeaf(FactorRequirement $requirement, array $pool, array $chosen, array $scopes): iterable
    {
        foreach ($pool as $candidate) {
            if ($this->leafMatches($requirement, $candidate) && $this->admissible($candidate, $chosen, $scopes)) {
                yield [...$chosen, $candidate];
            }
        }
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
     * @param list<SatisfiedFactor> $chosen
     * @param list<array{requirement: AllOf, from: int}> $scopes
     * @return iterable<list<SatisfiedFactor>>
     */
    private function solveAnyOf(AnyOf $requirement, array $pool, array $chosen, array $scopes): iterable
    {
        foreach ($requirement->requirements as $child) {
            yield from $this->solve($child, $pool, $chosen, $scopes);
        }
    }

    /**
     * @param list<SatisfiedFactor> $pool
     * @param list<SatisfiedFactor> $chosen
     * @param list<array{requirement: AllOf, from: int}> $scopes
     * @return iterable<list<SatisfiedFactor>>
     */
    private function solveAllOf(AllOf $requirement, array $pool, array $chosen, array $scopes): iterable
    {
        // This node's constraints bind every factor consumed anywhere beneath it,
        // including two that arrive from the same nested child. A child that waives
        // distinctness waives it for its own checking only; it can never license a
        // violation of an ancestor's requirement.
        $scopes[] = ['requirement' => $requirement, 'from' => count($chosen)];

        yield from $this->solveSequence($requirement->requirements, $pool, $chosen, $scopes);
    }

    /**
     * Satisfy $remaining left to right, backtracking into earlier requirements when a
     * later one cannot be met — the first match for one requirement is regularly the
     * only possible match for another.
     *
     * @param list<Requirement> $remaining
     * @param list<SatisfiedFactor> $pool
     * @param list<SatisfiedFactor> $chosen
     * @param list<array{requirement: AllOf, from: int}> $scopes
     * @return iterable<list<SatisfiedFactor>>
     */
    private function solveSequence(array $remaining, array $pool, array $chosen, array $scopes): iterable
    {
        if ($remaining === []) {
            yield $chosen;

            return;
        }

        $head = array_shift($remaining);

        foreach ($this->solve($head, $pool, $chosen, $scopes) as $extended) {
            yield from $this->solveSequence($remaining, $pool, $extended, $scopes);
        }
    }

    /**
     * Can $incoming join the factors already chosen? Checked against every enclosing
     * scope, so each unordered pair within a scope is validated exactly once, at the
     * step that completes it.
     *
     * @param list<SatisfiedFactor> $chosen
     * @param list<array{requirement: AllOf, from: int}> $scopes
     */
    private function admissible(SatisfiedFactor $incoming, array $chosen, array $scopes): bool
    {
        foreach ($scopes as $scope) {
            // A scope constrains only what was chosen inside it. Factors picked before
            // it opened belong to an ancestor and are checked under that ancestor.
            foreach (array_slice($chosen, $scope['from']) as $existing) {
                if (! $this->compatible($scope['requirement'], $existing, $incoming)) {
                    return false;
                }
            }
        }

        return true;
    }

    private function compatible(AllOf $requirement, SatisfiedFactor $existing, SatisfiedFactor $incoming): bool
    {
        if ($requirement->requireDistinctCredentials
            && $existing->credentialId === $incoming->credentialId) {
            return false;
        }

        if ($requirement->requireIndependentAuthenticators
            && $existing->authenticatorId !== null
            && $existing->authenticatorId === $incoming->authenticatorId) {
            return false;
        }

        return true;
    }
}
