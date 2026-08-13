<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/**
 * A recovery code opened the constrained capability.
 *
 * Distinct from Authenticated on purpose: the host guard is never invoked for
 * this result, and conflating the two is how a stolen recovery code would
 * become a broadly authenticated application session.
 */
final readonly class RecoveryGraceStarted implements FlowResult
{
    public function __construct(
        public int $userId,
        public string $boundContext,
        public ScreenSpec $screen,
    ) {}
}
