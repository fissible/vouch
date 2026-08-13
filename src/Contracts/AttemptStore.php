<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Attempts\ConflictingMutations;
use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Attempts\UnknownMutation;
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
     * Attempt a state transition, applying any single-use mutations atomically
     * with it.
     *
     * All-or-nothing: if any mutation's guard has already fired, the attempt
     * does not advance; if the attempt's CAS loses, every mutation is rolled
     * back. A driver must never write single-use state itself — a code burned
     * outside this transaction stays burned when the transition then fails.
     *
     * @throws ConflictingMutations when two mutations share a target.
     * @throws UnknownMutation when a mutation type cannot be executed.
     */
    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        SingleUseMutation ...$mutations,
    ): TransitionOutcome;
}
