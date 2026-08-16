<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use InvalidArgumentException;

/**
 * An already-canonicalized, domain-separated subject accepted by persistence.
 *
 * The store cannot accept a raw identifier or IP by accident: its API requires
 * this type, whose value is exactly one lowercase HMAC-SHA256 digest. The
 * dimension travels with the digest so a recovery key cannot silently enter an
 * identifier-lock row and an IPv4 bucket cannot consume the IPv6 threshold.
 */
final readonly class ThrottleSubject
{
    public function __construct(
        public ThrottleDimension $dimension,
        public string $digest,
    ) {
        if (preg_match('/\A[0-9a-f]{64}\z/D', $digest) !== 1) {
            throw new InvalidArgumentException(
                'A throttle subject must contain one lowercase HMAC-SHA256 digest.',
            );
        }
    }
}
