<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

final readonly class AssuranceFacts
{
    public function __construct(
        public int $distinctCredentialCount,
        public FactorStrength $strongest,
        public bool $allPhishingResistant,
        public bool $hasMultiFactorCredential,
        public ?DateTimeImmutable $weakestSatisfiedAt,
    ) {}

    /**
     * @param list<SatisfiedFactor> $factors
     */
    public static function fromFactors(array $factors): self
    {
        // Recovery grants a restricted recovery-grace session (spec §7.3); it never
        // contributes to a policy. Filtered here rather than relying on strength
        // ordering, so a policy with no minimum strength still cannot accept it.
        //
        // This deliberately duplicates the identical filter in
        // SatisfiabilityEvaluator::evaluate(). fromFactors() is a separate public
        // entry point that accepts any satisfaction list, not only a verdict's
        // usedFactors, so the invariant has to hold here on its own rather than by
        // assuming every caller pre-filtered. Without it a recovery-only set derives
        // one distinct credential and the NIST vocabulary names it `aal1` — an
        // ordinary single-factor level, indistinguishable from a password login.
        $eligible = array_values(array_filter(
            $factors,
            static fn (SatisfiedFactor $factor): bool => $factor->strength !== FactorStrength::Recovery,
        ));

        if ($eligible === []) {
            return new self(0, FactorStrength::Recovery, false, false, null);
        }

        $credentialIds = [];
        $strongest = FactorStrength::Recovery;
        $allPhishingResistant = true;
        $hasMultiFactorCredential = false;
        $oldest = null;

        foreach ($eligible as $factor) {
            $credentialIds[$factor->credentialId] = true;

            if ($factor->strength->atLeast($strongest)) {
                $strongest = $factor->strength;
            }

            if (! $factor->phishingResistant) {
                $allPhishingResistant = false;
            }

            if ($factor->isMultiFactor) {
                $hasMultiFactorCredential = true;
            }

            // Recency is governed by the oldest factor: a session is only as
            // fresh as its stalest evidence.
            if ($oldest === null || $factor->satisfiedAt < $oldest) {
                $oldest = $factor->satisfiedAt;
            }
        }

        return new self(
            distinctCredentialCount: count($credentialIds),
            strongest: $strongest,
            allPhishingResistant: $allPhishingResistant,
            hasMultiFactorCredential: $hasMultiFactorCredential,
            weakestSatisfiedAt: $oldest,
        );
    }
}
