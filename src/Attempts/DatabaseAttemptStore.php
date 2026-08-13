<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts;

use Fissible\Vouch\Attempts\Mutations\AdvanceCredentialTimestep;
use Fissible\Vouch\Attempts\Mutations\ConsumeChallenge;
use Fissible\Vouch\Attempts\Mutations\DisableCredential;
use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;
use Fissible\Vouch\Models\AuthAttempt;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Query\Builder as QueryBuilder;
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
        SingleUseMutation ...$mutations,
    ): TransitionOutcome {
        /*
         * PHP 8.1+ lets a variadic parameter receive named arguments, so its
         * native type is array<int|string, SingleUseMutation> rather than a
         * guaranteed list. Mutations are applied positionally, never by name;
         * reindexing makes that real rather than merely asserted.
         */
        $mutations = array_values($mutations);

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

        // Conflict detection is pure and costs no query, so it happens before
        // the transaction opens.
        $this->assertNoConflictingTargets($mutations);

        // Likewise pure: a ConsumeChallenge naming a different attempt than the
        // one being advanced is a programming error, not a race, and must never
        // reach a write.
        $this->assertMutationsTargetThisAttempt($attempt, $mutations);

        /*
         * Refusals are signalled by throwing, not by calling rollBack() inside
         * the closure. Laravel's transaction() owns the transaction lifecycle:
         * rolling back inside and then returning normally leaves it trying to
         * commit a transaction that no longer exists. Throwing is the mechanism
         * it actually supports, and it gives the same all-or-nothing guarantee.
         */
        try {
            $this->connection->transaction(function () use ($attempt, $to, $mutations): void {
                foreach ($mutations as $mutation) {
                    $this->apply($mutation);
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
     * @param list<SingleUseMutation> $mutations
     *
     * @throws ConflictingMutations
     */
    private function assertNoConflictingTargets(array $mutations): void
    {
        $seen = [];

        foreach ($mutations as $mutation) {
            $target = $mutation->target();

            if (isset($seen[$target])) {
                throw ConflictingMutations::forTarget($target);
            }

            $seen[$target] = true;
        }
    }

    /**
     * @param list<SingleUseMutation> $mutations
     *
     * @throws MisdirectedMutation
     */
    private function assertMutationsTargetThisAttempt(AuthAttempt $attempt, array $mutations): void
    {
        foreach ($mutations as $mutation) {
            if ($mutation instanceof ConsumeChallenge && $mutation->attemptId !== $attempt->id) {
                throw MisdirectedMutation::forChallenge($mutation, $attempt->id);
            }
        }
    }

    /**
     * Execute one guarded update, requiring it to affect exactly one row.
     *
     * Zero rows means the guard already fired — consumed, replayed, or
     * concurrently taken — and refuses. More than one means the predicate was
     * wrong; every predicate here is keyed on a primary key, so it cannot
     * happen, and refusing rather than trusting it is the cheap direction.
     *
     * Type dispatch lives here and nowhere else. There is deliberately no
     * pre-flight type check duplicating this match: a second list of known types
     * is a second thing to forget to update.
     *
     * @throws UnknownMutation
     */
    private function apply(SingleUseMutation $mutation): void
    {
        $affected = match (true) {
            $mutation instanceof ConsumeChallenge => $this->connection->table('auth_challenges')
                ->where('id', $mutation->challengeId)
                ->where('attempt_id', $mutation->attemptId)
                ->whereNull('consumed_at')
                ->where('expires_at', '>', $this->now())
                ->update(['consumed_at' => $this->now()]),

            $mutation instanceof DisableCredential => $this->connection->table('auth_credentials')
                ->where('id', $mutation->credentialId)
                ->whereNull('disabled_at')
                ->update(['disabled_at' => $this->now(), 'updated_at' => $this->now()]),

            $mutation instanceof AdvanceCredentialTimestep => $this->connection->table('auth_credentials')
                ->where('id', $mutation->credentialId)
                ->where(static fn (QueryBuilder $query): QueryBuilder => $query
                    ->whereNull('last_used_timestep')
                    ->orWhere('last_used_timestep', '<', $mutation->timestep))
                ->update([
                    'last_used_timestep' => $mutation->timestep,
                    'last_used_at' => $this->now(),
                    'updated_at' => $this->now(),
                ]),

            default => throw UnknownMutation::for($mutation),
        };

        if ($affected !== 1) {
            throw new TransitionRefused(match (true) {
                $mutation instanceof ConsumeChallenge => TransitionOutcome::ChallengeAlreadyConsumed,
                $mutation instanceof DisableCredential => TransitionOutcome::CredentialAlreadyConsumed,
                default => TransitionOutcome::TimestepReplay,
            });
        }
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
