<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

enum GraceStartOutcome
{
    case Opened;
    case Refused;
}
