<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use Symfony\Component\String\UnicodeString;

/**
 * Canonicalizes only syntax the package owns.
 *
 * Provider-specific aliases remain distinct: Vouch cannot assume Gmail dot
 * folding, plus addressing, or any other identity provider's ownership rules.
 */
final class IdentifierCanonicalizer
{
    public function canonicalize(string $identifier): string
    {
        return (new UnicodeString($identifier))
            ->lower()
            ->normalize()
            ->toString();
    }
}
