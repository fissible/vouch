<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use InvalidArgumentException;

/** Validated policy inputs for the delivery-facing spend boundary. */
final readonly class DeliveryEconomicsConfiguration
{
    /**
     * @param list<string> $smsAllowedCountries
     */
    public function __construct(
        public ?int $dailyCeilingMinor,
        public ?int $tenantCeilingMinor,
        public array $smsAllowedCountries,
    ) {
        foreach ([
            'dailyCeilingMinor' => $this->dailyCeilingMinor,
            'tenantCeilingMinor' => $this->tenantCeilingMinor,
        ] as $name => $ceiling) {
            if ($ceiling !== null && $ceiling < 1) {
                throw new InvalidArgumentException(sprintf('%s must be positive when configured.', $name));
            }
        }

        foreach ($this->smsAllowedCountries as $country) {
            if (preg_match('/\A[A-Z]{2}\z/D', $country) !== 1) {
                throw new InvalidArgumentException(sprintf(
                    'SMS country allow-list entries must be ISO uppercase pairs; got %s.',
                    $country,
                ));
            }
        }
    }
}
