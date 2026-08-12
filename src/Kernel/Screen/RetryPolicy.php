<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

use DateTimeImmutable;

/**
 * Only ever constructed with values the enumeration posture permits disclosing
 * (spec §7.1). Under strict posture the shaper passes nulls.
 */
final readonly class RetryPolicy
{
    public function __construct(
        public ?int $attemptsRemaining,
        public ?DateTimeImmutable $lockedUntil,
    ) {}
}
