<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

enum AssuranceOutcome
{
    case Sufficient;
    case InsufficientLevel;
    case InsufficientRecency;
    case InvalidEvidence;

    public function isSufficient(): bool
    {
        return $this === self::Sufficient;
    }
}
