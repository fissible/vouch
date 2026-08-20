<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

/** Worker reservation outcomes; retryable contention is not terminal. */
enum DeliveryReservationDecision
{
    case Permitted;
    case CountryNotAllowed;
    case SpendCeiling;
    case RetryableContention;
}
