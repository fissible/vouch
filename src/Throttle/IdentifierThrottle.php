<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use DateTimeImmutable;
use InvalidArgumentException;

/**
 * Authoritative submitted-identifier state.
 *
 * This is the only result capable of carrying lock state. Static factories make
 * a backed-off result without retryAfter, or a lock without lockedUntil,
 * unconstructable through the public API.
 */
final readonly class IdentifierThrottle
{
    private function __construct(
        public ThrottleDecision $decision,
        public ?int $attemptsRemaining,
        public ?DateTimeImmutable $lockedUntil,
        public ?DateTimeImmutable $retryAfter,
    ) {}

    public static function permitted(int $attemptsRemaining): self
    {
        self::requireRemaining($attemptsRemaining);

        return new self(
            ThrottleDecision::Permitted,
            $attemptsRemaining,
            null,
            null,
        );
    }

    public static function backedOff(int $attemptsRemaining, DateTimeImmutable $retryAfter): self
    {
        self::requireRemaining($attemptsRemaining);

        return new self(
            ThrottleDecision::BackedOff,
            $attemptsRemaining,
            null,
            $retryAfter,
        );
    }

    public static function locked(DateTimeImmutable $lockedUntil): self
    {
        return new self(
            ThrottleDecision::Locked,
            0,
            $lockedUntil,
            null,
        );
    }

    private static function requireRemaining(int $attemptsRemaining): void
    {
        if ($attemptsRemaining < 0) {
            throw new InvalidArgumentException('Attempts remaining cannot be negative.');
        }
    }
}
