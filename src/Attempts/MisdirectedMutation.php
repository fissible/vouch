<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use LogicException;

/**
 * A ConsumeChallenge named an attempt other than the one being advanced.
 *
 * ConsumeChallenge carries an attempt id specifically so the guarded update can
 * assert the challenge belongs to the attempt the transition is actually
 * advancing — without that cross-check, a caller could name attempt A's
 * challenge together with attempt A's id while the transition advances attempt
 * B, burning A's one-time code to authenticate B. That is a caller building the
 * request wrong, not a race, and it must never reach a write: the check is
 * pure and runs before the transaction opens, alongside ConflictingMutations.
 */
final class MisdirectedMutation extends LogicException
{
    public static function forChallenge(ConsumeChallenge $mutation, int $advancingAttemptId): self
    {
        return new self(sprintf(
            'ConsumeChallenge for challenge %d named attempt %d, but this transition is '
            . 'advancing attempt %d. A mutation must name the attempt it is actually being '
            . 'applied within.',
            $mutation->challengeId,
            $mutation->attemptId,
            $advancingAttemptId,
        ));
    }
}
