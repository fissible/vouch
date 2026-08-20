<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

/**
 * Immutable delivery metadata shared by the request preflight and worker
 * reservation. A decoy has no country; it can never become a spend target.
 */
final readonly class DeliveryEconomicsRequest
{
    public function __construct(
        public string $factorId,
        public string $channel,
        public ?string $tenantId,
        public ?string $country,
        public int $costMinor,
        public bool $decoy,
    ) {
        if ($this->costMinor < 0) {
            throw new \InvalidArgumentException('Delivery cost cannot be negative.');
        }

        if ($this->decoy && $this->country !== null) {
            throw new \InvalidArgumentException('A decoy delivery cannot carry a country target.');
        }
    }
}
