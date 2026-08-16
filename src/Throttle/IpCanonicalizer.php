<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use InvalidArgumentException;
use RuntimeException;

/**
 * Canonicalizes the host-resolved client IP for advisory throttling.
 *
 * IPv6 privacy addresses rotate freely inside a subscriber's allocation, so
 * the throttle subject is the first 64 bits rather than the individual address.
 */
final class IpCanonicalizer
{
    public function canonicalize(?string $ip): ?string
    {
        if ($ip === null) {
            return null;
        }

        $packed = @inet_pton($ip);

        if ($packed === false) {
            throw new InvalidArgumentException(sprintf(
                'The client IP "%s" is not a valid IP address.',
                $ip,
            ));
        }

        if (
            strlen($packed) === 16
            && bin2hex(substr($packed, 0, 12)) === '00000000000000000000ffff'
        ) {
            $packed = substr($packed, 12);
        } elseif (strlen($packed) === 16) {
            $packed = substr_replace($packed, str_repeat("\0", 8), 8, 8);
        }

        $canonical = inet_ntop($packed);

        if ($canonical === false) {
            throw new RuntimeException('The validated client IP could not be rendered.');
        }

        return $canonical;
    }
}
