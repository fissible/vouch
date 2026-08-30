<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

/**
 * The assurance-level ordering belongs to the domain: HTTP adapters use it,
 * but credentials, sessions, and authorization rules must not depend on HTTP.
 */
final class AssuranceLevelComparator
{
    /** @var list<string> Weakest first; the single assurance-level ordering. */
    public const ORDER = ['aal0', 'aal1', 'aal2', 'aal3'];

    public static function isKnown(string $level): bool
    {
        return in_array($level, self::ORDER, true);
    }

    public static function strength(string $level): int
    {
        $strength = array_search($level, self::ORDER, true);

        if (! is_int($strength)) {
            throw new \InvalidArgumentException('Unknown assurance level.');
        }

        return $strength;
    }
}
