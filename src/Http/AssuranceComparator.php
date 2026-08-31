<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

use Fissible\Vouch\Assurance\AssuranceLevelComparator;

/**
 * Backwards-compatible HTTP facade for the domain assurance ordering.
 *
 * HTTP still exposes this type to existing hosts, but the canonical ordering
 * lives in AssuranceLevelComparator because sessions and authorization also
 * make this policy decision without an HTTP dependency.
 */
final readonly class AssuranceComparator
{
    /** @var list<string> Weakest first; retained for HTTP consumer compatibility. */
    public const ORDER = AssuranceLevelComparator::ORDER;

    public static function isKnown(string $level): bool
    {
        return AssuranceLevelComparator::isKnown($level);
    }

    public static function strength(string $level): int
    {
        return AssuranceLevelComparator::strength($level);
    }
}
