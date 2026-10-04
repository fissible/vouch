<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

/**
 * #81. The documented common date-column range, not an authentication policy.
 *
 * MySQL DATETIME is the narrowest: 1000-01-01 through 9999-12-31. Measured,
 * MySQL stored year 0759 anyway, so asking an engine to accept the result is
 * not this check. Nor is a century cap: year 9000 is still representable.
 * Direction belongs to the consumer. 40,000,000,000 seconds reaches year
 * 3294 forward and 0759 backward; rejecting both would constrain unused time.
 *
 * Boot and doctor share this predicate without opening a database connection.
 * Execution supplies its database clock (or stored window start), because a
 * process may outlive boot and application time cannot authorize database SQL.
 *
 * @internal
 */
final class DurationBounds
{
    private function __construct() {}

    public static function forward(int $seconds, string $key, ?DateTimeImmutable $now = null): int
    {
        return self::check($seconds, $key, $now, false, 1);
    }

    public static function backward(int $seconds, string $key, ?DateTimeImmutable $now = null): int
    {
        return self::check($seconds, $key, $now, true, 1);
    }

    public static function backwardDays(int $days, string $key, ?DateTimeImmutable $now = null): int
    {
        return self::check($days, $key, $now, true, 86400);
    }

    /** @param 1|86400 $secondsPerUnit */
    private static function check(
        int $value,
        string $key,
        ?DateTimeImmutable $now,
        bool $backward,
        int $secondsPerUnit,
    ): int {
        if ($value < 1) {
            throw ConfigurationError::positiveInteger($value, $key);
        }

        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $floor = new DateTimeImmutable('1000-01-01 00:00:00', $now->getTimezone());
        $ceiling = new DateTimeImmutable('9999-12-31 23:59:59', $now->getTimezone());
        $available = $backward
            ? $now->getTimestamp() - $floor->getTimestamp()
            : $ceiling->getTimestamp() - $now->getTimestamp();

        // Divide the available range, never multiply untrusted days or add an
        // untrusted duration to now: PHP_INT_MAX must refuse before overflow.
        // 500000 days reaches year 0657; treating it as seconds hid that defect.
        if ($now < $floor || $now > $ceiling || $value > intdiv($available, $secondsPerUnit)) {
            throw new InvalidArgumentException(sprintf(
                'Configuration "%s" must describe an instant from 1000-01-01 00:00:00 '
                . 'through 9999-12-31 23:59:59 going %s; got %s.',
                $key,
                $backward ? 'backward' : 'forward',
                ConfigurationError::describe($value),
            ));
        }

        return $value;
    }
}
