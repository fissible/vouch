<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * A single-use state change that only the attempt store may execute.
 *
 * Typed value objects rather than driver-supplied SQL: the store knows how to
 * execute each one, so there is no injection surface and every single-use
 * mutation in the package is auditable in one place.
 */
interface SingleUseMutation
{
    /**
     * Stable conflict key, e.g. "credential:17" or "challenge:42".
     *
     * Two mutations sharing a target in one transition are a programming error.
     */
    public function target(): string;
}
