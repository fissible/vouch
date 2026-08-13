<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use LogicException;

/**
 * The store was handed a mutation type it cannot execute.
 *
 * PHP has no sealed interfaces, so a future driver can implement
 * SingleUseMutation with something the store has never seen. Skipping it would
 * silently drop a single-use guard — a spent recovery code left live, a replayed
 * timestep accepted — which is exactly the failure this design exists to
 * prevent. Throwing from inside the transaction aborts and rolls back.
 */
final class UnknownMutation extends LogicException
{
    public static function for(SingleUseMutation $mutation): self
    {
        return new self(sprintf(
            'DatabaseAttemptStore cannot execute %s (target "%s"). Every single-use '
            . 'mutation must be a type the store knows how to guard; add it there rather '
            . 'than writing the state from a driver.',
            $mutation::class,
            $mutation->target(),
        ));
    }
}
