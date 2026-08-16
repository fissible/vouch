<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

/** Explicit online-throttle outcomes; no nullable field combination is a state. */
enum ThrottleDecision
{
    case Observed;
    case Permitted;
    case BackedOff;
    case Locked;
    case Skipped;
}
