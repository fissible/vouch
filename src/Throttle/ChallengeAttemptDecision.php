<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

/** Result of atomically recording one failed code against one challenge. */
enum ChallengeAttemptDecision
{
    case Remaining;
    case Invalidated;
    case Expired;
    case Consumed;
    case Unavailable;
}
