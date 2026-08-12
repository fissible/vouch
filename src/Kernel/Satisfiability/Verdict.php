<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Satisfiability;

use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

final readonly class Verdict
{
    /**
     * @param list<SatisfiedFactor> $usedFactors
     */
    private function __construct(
        public bool $satisfied,
        public array $usedFactors,
    ) {}

    public static function unsatisfied(): self
    {
        return new self(false, []);
    }

    /**
     * @param list<SatisfiedFactor> $factors
     */
    public static function satisfiedBy(array $factors): self
    {
        return new self(true, $factors);
    }
}
