<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

/** No nullable combinations: either delivery economics permits or refuses. */
enum DeliveryEconomicsDecision
{
    case Permitted;
    case Refused;
}
