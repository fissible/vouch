<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

/**
 * Moves the provisional Vouch-session binding to Laravel's post-login session.
 */
interface SessionRebinder
{
    public function rebind(string $previousBinding, int $userId): void;
}
