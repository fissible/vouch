<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use DateTimeImmutable;

/**
 * Advisory state for recovery, IP, tenant, and global dimensions.
 *
 * No property can carry attempts remaining or lockedUntil. A shared caller can
 * report measured retryAfter or skip a contended observation, but cannot become
 * an identifier-lock authority through inattention.
 */
final readonly class SharedThrottle
{
    private function __construct(
        public ThrottleDecision $decision,
        public ?DateTimeImmutable $retryAfter,
    ) {}

    public static function observed(): self
    {
        return new self(ThrottleDecision::Observed, null);
    }

    public static function permitted(): self
    {
        return new self(ThrottleDecision::Permitted, null);
    }

    public static function backedOff(DateTimeImmutable $retryAfter): self
    {
        return new self(ThrottleDecision::BackedOff, $retryAfter);
    }

    public static function skipped(): self
    {
        return new self(ThrottleDecision::Skipped, null);
    }
}
