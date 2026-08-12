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
        if ($factors === []) {
            return new self(0, FactorStrength::Recovery, false, false, null);
        }

        $credentialIds = [];
        $strongest = FactorStrength::Recovery;
        $allPhishingResistant = true;
        $hasMultiFactorCredential = false;
        $oldest = null;

        foreach ($factors as $factor) {
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
