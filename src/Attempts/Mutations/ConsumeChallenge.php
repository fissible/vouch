<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * Burn a delivered challenge code.
 *
 * Carries the attempt id as well as the challenge id so the guarded update can
 * assert the challenge belongs to the attempt being advanced. Without it, a
 * challenge id leaked from another attempt would consume cleanly.
 */
final readonly class ConsumeChallenge implements SingleUseMutation
{
    public function __construct(
        public int $challengeId,
        public int $attemptId,
    ) {}

    public function target(): string
    {
        return 'challenge:' . $this->challengeId;
    }
}
