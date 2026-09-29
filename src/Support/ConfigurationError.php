<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use InvalidArgumentException;

/**
 * Shared operator-facing vocabulary; callers own their value acceptance rules.
 *
 * @internal
 */
final class ConfigurationError
{
    private function __construct() {}

    public static function positiveInteger(mixed $value, string $key): InvalidArgumentException
    {
        return new InvalidArgumentException(sprintf(
            'Configuration "%s" must be a positive integer; got %s.',
            $key,
            self::describe($value),
        ));
    }

    public static function describe(mixed $value): string
    {
        return match (true) {
            $value === '' => 'an empty string',
            is_string($value) => 'string "' . $value . '"',
            is_int($value) => (string) $value,
            $value === null => 'null',
            default => get_debug_type($value),
        };
    }
}
