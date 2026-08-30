<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

final readonly class AssuranceComparison
{
    public function __construct(public AssuranceOutcome $outcome, public AssuranceReason $reason) {}
}
