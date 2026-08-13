<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

/**
 * The result of attempting an attempt-state transition.
 *
 * Every non-success value is a refusal, and every refusal leaves the stored
 * attempt and any named challenge exactly as they were.
 */
enum TransitionOutcome: string
{
    case Succeeded = 'succeeded';

    /** The kernel's TransitionRules rejected the move. Nothing was written. */
    case IllegalTransition = 'illegal_transition';

    /** The attempt has passed its hard expiry. */
    case Expired = 'expired';

    /** Presented from a session context other than the one it was bound to. */
    case ContextMismatch = 'context_mismatch';

    /** The challenge was already consumed or has expired. */
    case ChallengeAlreadyConsumed = 'challenge_already_consumed';

    /** Lost the compare-and-swap: another writer advanced the attempt first. */
    case ConcurrentModification = 'concurrent_modification';
}
