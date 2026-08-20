<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Delivery\DeliveryEconomicsDecision;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Delivery\DeliveryReservationDecision;

final class PermittingDeliveryEconomics implements DeliveryEconomics
{
    /** @var list<DeliveryEconomicsRequest> */
    public array $preflights = [];

    public DeliveryEconomicsDecision $preflightDecision = DeliveryEconomicsDecision::Permitted;

    public function preflight(DeliveryEconomicsRequest $request): DeliveryEconomicsDecision
    {
        $this->preflights[] = $request;

        return $this->preflightDecision;
    }

    public function reserve(DeliveryEconomicsRequest $request): DeliveryReservationDecision
    {
        return DeliveryReservationDecision::Permitted;
    }
}
