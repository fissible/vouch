<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use Fissible\Vouch\Contracts\DeliveryEconomics;
use RuntimeException;

/** Fail closed until the host binds a real 2.3c economics implementation. */
final readonly class UnconfiguredDeliveryEconomics implements DeliveryEconomics
{
    public static function exception(): RuntimeException
    {
        return new RuntimeException(
            'No OTP delivery economics is configured. Bind '
            . 'Fissible\\Vouch\\Contracts\\DeliveryEconomics before enabling email or SMS OTP.',
        );
    }

    public function preflight(DeliveryEconomicsRequest $request): DeliveryEconomicsDecision
    {
        throw self::exception();
    }

    public function reserve(DeliveryEconomicsRequest $request): DeliveryReservationDecision
    {
        throw self::exception();
    }
}
