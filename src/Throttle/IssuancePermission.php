<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

/** Result of charging one issuance event before target resolution. */
enum IssuancePermission
{
    case Permitted;
    case Refused;
}
