<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

/**
 * The outcome of a verification, plus any single-use state the store must write.
 *
 * This is the seam between Phase 2 and Phase 1. The driver is the only component
 * that knows whether user verification actually occurred, whether its mechanism
 * is phishing-resistant, and which credential was used; it reports those
 * honestly and hands them over. The kernel decides satisfiability.
 *
 * Drivers never evaluate policy, and they never write the mutations they return.
 */
final readonly class FactorResult
{
    /**
     * @param  list<SingleUseMutation>  $mutations
     */
    private function __construct(
        public ?SatisfiedFactor $factor,
        public ?FactorFailure $failure,
        public array $mutations,
    ) {}

    public static function satisfied(SatisfiedFactor $factor, SingleUseMutation ...$mutations): self
    {
        return new self($factor, null, array_values($mutations));
    }

    public static function failed(FactorFailure $reason): self
    {
        return new self(null, $reason, []);
    }

    /**
     * @phpstan-assert-if-true !null $this->factor
     * @phpstan-assert-if-false !null $this->failure
     */
    public function isSatisfied(): bool
    {
        return $this->factor !== null;
    }
}
