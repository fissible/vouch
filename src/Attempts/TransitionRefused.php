<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use RuntimeException;

/**
 * Internal control-flow signal for a refused transition.
 *
 * Thrown inside the store's transaction closure so Laravel rolls the
 * transaction back through its own mechanism, then caught immediately by the
 * store and converted to a TransitionOutcome. It never escapes the store, and
 * callers never see it.
 *
 * Throwing rather than calling rollBack() inside the closure is deliberate:
 * transaction() owns the lifecycle, so rolling back inside and returning
 * normally leaves it trying to commit a transaction that no longer exists.
 */
final class TransitionRefused extends RuntimeException
{
    public function __construct(public readonly TransitionOutcome $outcome)
    {
        parent::__construct('Transition refused: ' . $outcome->value);
    }
}
