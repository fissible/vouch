<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

/**
 * An optional vocabulary capability for reporting its authoritative range.
 */
interface ReportsReachableLevels
{
    /** @return list<string> */
    public function reachableLevels(): array;
}
