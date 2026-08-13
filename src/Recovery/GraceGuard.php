<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Connection;

/**
 * Resolves the recovery-grace capability, entirely in database time.
 *
 * NEVER load a row and compare recovery_grace_expires_at to PHP's now(). That
 * recreates the application/database clock seam documented on
 * DatabaseAttemptStore::now() — the one that silently invalidated Phase 2.2's
 * TOTP tests, which were green only while real time happened to sit before a
 * frozen expiry.
 *
 * A grace record is an auth_sessions row bound to an ANONYMOUS host session:
 * vouch knows who it is, the host guard does not. That is what makes a stolen
 * recovery code a constrained capability rather than an application session.
 */
final readonly class GraceGuard
{
    public function __construct(
        private Connection $connection,
        private DatabaseTime $time,
        private int $ttlSeconds,
    ) {}

    /**
     * Open the constrained capability for this anonymous host session.
     *
     * The deadline is written with the database's own clock, so the window is
     * nominally $ttlSeconds rather than $ttlSeconds plus or minus drift.
     */
    public function start(string $hostSessionId, int $userId): void
    {
        $this->connection->table('auth_sessions')->updateOrInsert(
            ['session_binding' => SessionBinding::for($hostSessionId, BindingDomain::Session)],
            [
                'user_id' => $userId,
                'amr' => json_encode(['recovery_code']),
                'acr' => null,
                'revoked_at' => null,
                'revoked_reason' => null,
                'created_at' => $this->time->now(),
                'updated_at' => $this->time->now(),
            ],
        );

        /*
         * The deadline is set in a second statement so the seconds can be a
         * BOUND parameter: interval arithmetic differs per engine, and every
         * per-engine fragment is a true literal with a placeholder rather than
         * an interpolated int. Written with the database's own clock, so the
         * window is nominally $ttlSeconds rather than that plus or minus drift.
         */
        $this->connection->update(
            'update auth_sessions set recovery_grace_expires_at = '
            . $this->time->deadlineSqlHere()
            . ' where session_binding = ?',
            [$this->ttlSeconds, SessionBinding::for($hostSessionId, BindingDomain::Session)],
        );
    }

    /** The live grace record for this host session, or null. */
    public function activeFor(string $hostSessionId): ?AuthSession
    {
        return AuthSession::query()
            ->where('session_binding', SessionBinding::for($hostSessionId, BindingDomain::Session))
            ->whereNotNull('recovery_grace_expires_at')
            ->whereNull('revoked_at')
            // The predicate, not a PHP comparison.
            ->where('recovery_grace_expires_at', '>', $this->time->now())
            ->first();
    }

    /**
     * Mark a lapsed grace row expired — without overwriting a prior reason.
     *
     * The `revoked_at IS NULL` guard is the same shape as 2.2's
     * DisableCredential predicate. If the row was already admin_revoked, the
     * update affects no rows and the existing reason stands. The session is
     * destroyed and grace routes refuse either way; only the audit record
     * differs, and a false entry there is produced by the system itself rather
     * than by an attacker.
     */
    public function expireIfLapsed(string $hostSessionId): void
    {
        $this->connection->table('auth_sessions')
            ->where('session_binding', SessionBinding::for($hostSessionId, BindingDomain::Session))
            ->whereNotNull('recovery_grace_expires_at')
            ->whereNull('revoked_at')
            ->where('recovery_grace_expires_at', '<=', $this->time->now())
            ->update([
                'revoked_at' => $this->time->now(),
                'revoked_reason' => RevokedReason::GraceExpired->value,
            ]);
    }
}
