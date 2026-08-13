<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;

/**
 * Persists in-progress authentication attempts.
 *
 * Responsibility split: the Phase 1 kernel's TransitionRules decides whether a
 * transition is *legal*; the store decides whether the caller *won the race*.
 * An implementation must never re-implement legality.
 */
interface AttemptStore
{
    /**
     * Attempt a state transition, optionally consuming a challenge atomically
     * with it.
     *
     * When $consumeChallengeId is given, the challenge consumption and the
     * attempt advance are all-or-nothing: if the challenge was already consumed
     * or has expired, the attempt does not advance; if the attempt's CAS loses,
     * the consumption is rolled back.
     */
    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        ?int $consumeChallengeId = null,
    ): TransitionOutcome;
}
