<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Models\AuthAttempt;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Expression;

final class DatabaseAttemptStore implements AttemptStore
{
    public function __construct(
        private readonly ConnectionInterface $connection,
        private readonly TransitionRules $rules,
    ) {}

    public function transition(
        AuthAttempt $attempt,
        AttemptState $to,
        ?int $consumeChallengeId = null,
    ): TransitionOutcome {
        // Legality is the kernel's decision, and costs no write.
        if (! $this->rules->allows($attempt->state, $to)) {
            return TransitionOutcome::IllegalTransition;
        }

        $stored = AuthAttempt::query()->find($attempt->id);

        if (! $stored instanceof AuthAttempt) {
            return TransitionOutcome::ConcurrentModification;
        }

        if ($stored->bound_context !== $attempt->bound_context) {
            return TransitionOutcome::ContextMismatch;
        }

        /*
         * Refusals are signalled by throwing, not by calling rollBack() inside
         * the closure. Laravel's transaction() owns the transaction lifecycle:
         * rolling back inside and then returning normally leaves it trying to
         * commit a transaction that no longer exists. Throwing is the mechanism
         * it actually supports, and it gives the same all-or-nothing guarantee.
         */
        try {
            $this->connection->transaction(function () use ($attempt, $to, $consumeChallengeId): void {
                if ($consumeChallengeId !== null) {
                    $consumed = $this->connection->table('auth_challenges')
                        ->where('id', $consumeChallengeId)
                        ->where('attempt_id', $attempt->id)
                        ->whereNull('consumed_at')
                        ->where('expires_at', '>', $this->now())
                        ->update(['consumed_at' => $this->now()]);

                    if ($consumed !== 1) {
                        throw new TransitionRefused(TransitionOutcome::ChallengeAlreadyConsumed);
                    }
                }

                $advanced = $this->connection->table('auth_attempts')
                    ->where('id', $attempt->id)
                    ->where('version', $attempt->version)
                    ->where('expires_at', '>', $this->now())
                    ->update([
                        'state' => $to->value,
                        'version' => new Expression('version + 1'),
                        'updated_at' => $this->now(),
                    ]);

                if ($advanced !== 1) {
                    throw new TransitionRefused($this->expiredOrLostRace($attempt));
                }
            });
        } catch (TransitionRefused $refused) {
            return $refused->outcome;
        }

        return TransitionOutcome::Succeeded;
    }

    /**
     * The database's current time, evaluated at statement execution.
     *
     * Deliberately NOT an application timestamp bound as a parameter. A
     * pre-flight check alone leaves a time-of-check/time-of-use window: the row
     * passes at T0, expires at T0.5, and the update still lands at T1. Binding
     * T0 would not close it — the predicate would compare against T0 and pass.
     * Evaluating at statement execution does. It follows that expires_at values
     * are written with the same clock, so no app-to-database skew can widen or
     * narrow a lifetime.
     *
     * @return Expression<'CURRENT_TIMESTAMP'>
     */
    private function now(): Expression
    {
        return new Expression('CURRENT_TIMESTAMP');
    }

    /**
     * Distinguish "expired" from "lost the CAS" for a refused advance. Both
     * refuse; the caller deserves to know which.
     */
    private function expiredOrLostRace(AuthAttempt $attempt): TransitionOutcome
    {
        $stillLive = $this->connection->table('auth_attempts')
            ->where('id', $attempt->id)
            ->where('expires_at', '>', $this->now())
            ->exists();

        return $stillLive
            ? TransitionOutcome::ConcurrentModification
            : TransitionOutcome::Expired;
    }
}
