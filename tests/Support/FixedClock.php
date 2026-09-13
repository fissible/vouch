<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * An application clock frozen at a chosen instant.
 *
 * Deadlines written on the database clock and compared against this one are
 * nominally N seconds and actually N seconds plus whatever skew exists between
 * the two machines. Freezing the application clock at a known offset from the
 * database's own time makes that skew a fixed, asserted quantity rather than a
 * drift a test would have to be lucky to observe.
 */
final class FixedClock implements ClockInterface
{
    public function __construct(private readonly DateTimeImmutable $now) {}

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }
}
