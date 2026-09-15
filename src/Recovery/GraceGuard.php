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
    public function start(string $hostSessionId, int $userId): GraceStartOutcome
    {
        $binding = SessionBinding::for($hostSessionId, BindingDomain::Session);

        return $this->connection->transaction(function () use ($binding, $userId): GraceStartOutcome {
            /*
             * Ensure before reading: even an ignored insert takes SQLite's
             * write lock, avoiding a deferred read-to-write upgrade. Existing
             * rows stay untouched, including their ownership and audit fields.
             */
            $this->connection->table('auth_sessions')->insertOrIgnore([
                'session_binding' => $binding,
                'user_id' => $userId,
                'amr' => json_encode(['recovery_code']),
                'created_at' => $this->time->now(),
                'updated_at' => $this->time->now(),
            ]);

            // A locking re-read sees any revocation that won the race and
            // keeps later revocations serialized through the grace writes.
            // Ownership matters even on live rows: reset acts on their user_id.
            $session = $this->connection->table('auth_sessions')
                ->where('session_binding', $binding)
                ->whereNull('revoked_at')
                ->where('user_id', $userId)
                ->lockForUpdate()
                ->first();

            if ($session === null) {
                return GraceStartOutcome::Refused;
            }

            $this->connection->table('auth_sessions')
                ->where('session_binding', $binding)
                ->update([
                    'amr' => json_encode(['recovery_code']),
                    'acr' => null,
                    'updated_at' => $this->time->now(),
                ]);

            /*
             * The deadline is set separately so the seconds remain a bound
             * parameter in each engine's database-clock interval expression.
             * The transaction keeps the capability and its evidence atomic.
             */
            $this->connection->update(
                'update auth_sessions set recovery_grace_expires_at = '
                . $this->time->deadlineSqlHere()
                . ' where session_binding = ?',
                [$this->ttlSeconds, $binding],
            );

            return GraceStartOutcome::Opened;
        });
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
