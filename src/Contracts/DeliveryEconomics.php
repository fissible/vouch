<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Delivery\DeliveryEconomicsDecision;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Delivery\DeliveryReservationDecision;

/**
 * Authorizes delivery economics in two deliberately different phases.
 *
 * preflight() is a target-independent request-path fast-fail. reserve() is the
 * worker-side authoritative check-and-act operation and may therefore use the
 * resolved delivery country and must enforce spend atomically.
 */
interface DeliveryEconomics
{
    public function preflight(DeliveryEconomicsRequest $request): DeliveryEconomicsDecision;

    public function reserve(DeliveryEconomicsRequest $request): DeliveryReservationDecision;
}
