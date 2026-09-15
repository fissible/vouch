<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/**
 * No capability opened, and the completed attempt cannot offer another challenge.
 */
final readonly class RecoveryGraceRefused implements FlowResult
{
    // CredentialRejected describes the refused capability without distinguishing
    // binding ownership or history, even under friendly enumeration posture.
    public Outcome $reason;

    public function __construct(
        public ScreenSpec $screen,
    ) {
        $this->reason = Outcome::CredentialRejected;
    }
}
