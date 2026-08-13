<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use LogicException;

/**
 * Two single-use mutations named the same target in one transition.
 *
 * A LogicException rather than a TransitionOutcome: this is not a race a caller
 * can lose, it is a caller that built the request wrong. Silently applying both
 * or picking one would make the result depend on argument order.
 */
final class ConflictingMutations extends LogicException
{
    public static function forTarget(string $target): self
    {
        return new self(sprintf(
            'Two single-use mutations both target "%s" in one transition. Exactly one '
            . 'mutation may apply to a target per transition; applying both would make '
            . 'the outcome depend on argument order.',
            $target,
        ));
    }
}
