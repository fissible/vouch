<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use InvalidArgumentException;

/** The single factor-to-provider channel mapping used at both boundaries. */
final class DeliveryChannel
{
    public static function fromFactor(string $factorId): string
    {
        return match ($factorId) {
            'email_otp' => 'email',
            'sms_otp' => 'sms',
            default => throw new InvalidArgumentException(sprintf(
                'Factor "%s" has no delivery economics channel.',
                $factorId,
            )),
        };
    }
}
