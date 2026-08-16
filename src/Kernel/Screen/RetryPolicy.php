<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

use DateTimeImmutable;

/**
 * Only ever constructed with values the enumeration posture permits disclosing
 * (spec §7.1). attemptsRemaining is posture-sensitive counter state;
 * lockedUntil is populated only by the submitted-identifier lock writer;
 * retryAfter is a measured ordinary-backoff deadline that may survive strict
 * posture only while known and nonexistent identifiers advance identically.
 */
final readonly class RetryPolicy
{
    public function __construct(
        public ?int $attemptsRemaining,
        public ?DateTimeImmutable $lockedUntil,
        public ?DateTimeImmutable $retryAfter = null,
    ) {}
}
