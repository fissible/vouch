<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Throttle\IssuancePermission;

/** Result of the target-independent volume step. */
final readonly class ChallengeIssuanceTicket
{
    public function __construct(
        public ChallengeIssuanceIntent $intent,
        public IssuancePermission $permission,
    ) {}
}
