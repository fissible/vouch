<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

/** Canonical SMS target and the ISO country used by delivery economics. */
final readonly class NormalizedPhoneNumber
{
    public function __construct(
        public string $e164,
        public string $country,
    ) {}
}
