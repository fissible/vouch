<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Fissible\Vouch\Contracts\RandomSource;

/**
 * The production source: PHP's CSPRNG, unwrapped and unembellished.
 *
 * random_int() throws on failure rather than returning weak output, and that
 * behaviour is deliberately not caught here — a system that cannot produce
 * secure randomness must not fall back to producing insecure recovery codes.
 */
final class SystemRandomSource implements RandomSource
{
    public function int(int $min, int $max): int
    {
        return random_int($min, $max);
    }
}
