<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use Fissible\Vouch\Models\AuthSession;
use Illuminate\Contracts\Session\Session;

/**
 * Rebinds an existing live row after the host guard migrates its session ID.
 */
final readonly class DatabaseSessionRebinder implements SessionRebinder
{
    public function __construct(private Session $session) {}

    public function rebind(string $previousBinding, int $userId): void
    {
        $binding = SessionBinding::for($this->session->getId(), BindingDomain::Session);

        $target = AuthSession::query()
            ->where('user_id', $userId)
            ->where('session_binding', $previousBinding)
            ->whereNull('revoked_at');

        /*
         * MySQL reports zero affected rows when the host guard did not
         * migrate its session and the binding is already correct. Verify that
         * exact live row rather than mistaking its no-op update for a lost
         * provisional row.
         */
        if ($previousBinding === $binding) {
            if (! $target->exists()) {
                throw new \RuntimeException('The live provisional session could not be rebound.');
            }

            return;
        }

        $rebound = $target->update(['session_binding' => $binding]);

        if ($rebound === 0) {
            throw new \RuntimeException('The live provisional session could not be rebound.');
        }
    }
}
