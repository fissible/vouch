<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * Burn a delivered challenge code.
 *
 * Carries the attempt id as well as the challenge id so the store can assert
 * the challenge belongs to the attempt being advanced: a pre-flight check
 * rejects an attemptId that doesn't match the attempt the transition is
 * actually advancing, and the guarded update's attempt_id conjunct rejects an
 * attemptId that doesn't match the challenge's true owner. Without both, a
 * challenge id leaked from another attempt could consume cleanly.
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
