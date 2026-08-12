<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

use DateInterval;
use Psr\Clock\ClockInterface;

final readonly class AssuranceLevel
{
    public function __construct(
        public string $acr,
        public AssuranceFacts $facts,
    ) {}

    public function satisfiesRecency(DateInterval $maxAge, ClockInterface $clock): bool
    {
        $oldest = $this->facts->weakestSatisfiedAt;

        if ($oldest === null) {
            return false;
        }

        return $oldest >= $clock->now()->sub($maxAge);
    }
}
