<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use DateInterval;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Tokens\TokenAssuranceSweep;
use Fissible\Vouch\Tokens\TokenAssuranceSweepResult;
use Illuminate\Console\Command;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use RuntimeException;
use Throwable;

/**
 * Housekeeping only.
 *
 * This command reaps dead rows. It is never the enforcement mechanism for any
 * expiry: attempt expiry is enforced in the store's guarded UPDATE predicates,
 * and recovery-grace expiry is enforced per-request on every vouch-owned route.
 *
 * In particular it does NOT delete sessions whose recovery grace has lapsed.
 * Doing so would turn a rejected grace session into an anonymous one for any
 * request arriving before the sweep, making the sweep the enforcement it must
 * never be.
 */
final class VouchPruneCommand extends Command
{
    protected $signature = 'vouch:prune';

    protected $description = 'Prune expired Vouch security state and classify OTP delivery health.';

    public function handle(DatabaseTime $time, ThrottleConfiguration $throttle, TokenAssuranceSweep $tokenAssurances): int
    {
        try {
            $result = $this->sweep(DB::connection(), $time, $throttle);
        } catch (Throwable $exception) {
            $this->components->error(sprintf(
                'Vouch prune failed before delivery health could be classified: %s',
                $exception->getMessage(),
            ));

            return CommandExit::Failure->value;
        }

        try {
            $tokenResult = $tokenAssurances->sweep();
        } catch (Throwable $exception) {
            $tokenResult = new TokenAssuranceSweepResult(
                reclaimed: 0,
                retained: 0,
                unsupported: 0,
                errored: 1,
                errors: [sprintf('token assurance sweep: %s', $exception->getMessage())],
            );
        }

        $result = new PruneResult(
            attempts: $result->attempts,
            challenges: $result->challenges,
            revokedSessions: $result->revokedSessions,
            throttleCounters: $result->throttleCounters,
            expiredLocks: $result->expiredLocks,
            tupleMarkers: $result->tupleMarkers,
            deliveredOutbox: $result->deliveredOutbox,
            undeliveredOutbox: $result->undeliveredOutbox,
            deliveryReservations: $result->deliveryReservations,
            reclaimedTokenAssurances: $tokenResult->reclaimed,
            retainedTokenAssurances: $tokenResult->retained,
            unsupportedTokenAssurances: $tokenResult->unsupported,
            erroredTokenAssurances: $tokenResult->errored,
            tokenAssuranceSweepErrors: $tokenResult->errors,
            unsupportedTokenAssuranceIssuers: $tokenResult->unsupportedIssuers,
        );

        $this->components->info(sprintf(
            'Pruned %d attempt(s), %d challenge(s), %d revoked session(s), '
            . '%d throttle counter(s), %d expired identifier lock(s), '
            . '%d tuple marker(s), %d delivered OTP outbox row(s), and '
            . '%d expired-undelivered OTP outbox row(s), and %d delivery reservation(s).',
            $result->attempts,
            $result->challenges,
            $result->revokedSessions,
            $result->throttleCounters,
            $result->expiredLocks,
            $result->tupleMarkers,
            $result->deliveredOutbox,
            $result->undeliveredOutbox,
            $result->deliveryReservations,
        ));

        $this->components->info(sprintf(
            'Token assurance sweep records: reclaimed %d, retained %d, unsupported %d, errored %d.',
            $result->reclaimedTokenAssurances,
            $result->retainedTokenAssurances,
            $result->unsupportedTokenAssurances,
            $result->erroredTokenAssurances,
        ));

        foreach ($result->tokenAssuranceSweepErrors as $error) {
            $this->components->warn(sprintf('Token assurance sweep error: %s', $error));
        }

        if ($result->unsupportedTokenAssuranceIssuers !== []) {
            $this->components->warn(sprintf(
                'Unsupported token assurance issuer(s): %s',
                implode(', ', $result->unsupportedTokenAssuranceIssuers),
            ));
        }

        if ($result->foundUndeliveredWork()) {
            $this->components->warn(sprintf(
                'Found %d expired undelivered OTP delivery row(s). Pruning succeeded; '
                . 'route this alert to delivery-worker health.',
                $result->undeliveredOutbox,
            ));

            return CommandExit::DeliveryHealth->value;
        }

        return CommandExit::Success->value;
    }

    private function sweep(
        Connection $connection,
        DatabaseTime $time,
        ThrottleConfiguration $throttle,
    ): PruneResult {
        $retentionDays = Config::integer('vouch.sessions.revocation_retention_days');

        if ($retentionDays < 1) {
            throw new InvalidArgumentException(
                'Configuration "vouch.sessions.revocation_retention_days" must be at least 1.',
            );
        }

        return $connection->transaction(function () use (
            $connection,
            $time,
            $throttle,
            $retentionDays,
        ): PruneResult {
            $now = $time->current();
            $sessionCutoff = $now->sub(new DateInterval(sprintf('P%dD', $retentionDays)));
            $scalarCutoff = $now->sub(new DateInterval(sprintf(
                'PT%dS',
                $throttle->retentionSeconds,
            )));
            $tupleCutoff = $now->sub(new DateInterval(sprintf(
                'PT%dS',
                $throttle->windowSeconds,
            )));
            $currentDeliveryWindow = $now->format('Y-m-d 00:00:00');

            /*
             * Classify outbox rows before any attempt cascade can delete them.
             * The concrete database timestamp is shared by every query in this
             * sweep, so crossing the deadline mid-command cannot change which
             * rows were counted versus removed.
             */
            $expiredOutboxes = $connection->table('auth_challenge_outbox')
                ->where('expires_at', '<=', $now)
                ->lockForUpdate()
                ->get(['id', 'status']);
            $outboxIds = [];
            $deliveredOutbox = 0;
            $undeliveredOutbox = 0;

            foreach ($expiredOutboxes as $row) {
                $attributes = (array) $row;
                $id = $attributes['id'] ?? null;
                $status = $attributes['status'] ?? null;

                if (! is_int($id) || ! is_string($status)) {
                    throw new RuntimeException('The database returned an invalid OTP outbox row.');
                }

                $outboxIds[] = $id;

                if ($status === OtpOutboxStatus::Delivered->value) {
                    $deliveredOutbox++;
                } else {
                    $undeliveredOutbox++;
                }
            }

            if ($outboxIds !== []) {
                $connection->table('auth_challenge_outbox')->whereIn('id', $outboxIds)->delete();
            }

            $challenges = $connection->table('auth_challenges')
                ->join('auth_attempts', 'auth_attempts.id', '=', 'auth_challenges.attempt_id')
                ->where('auth_attempts.expires_at', '<=', $now)
                ->count();

            /*
             * Query-builder deletes rather than Eloquent's: model events are
             * not part of housekeeping, and every count here is the actual
             * affected-row result committed by this transaction.
             */
            $attempts = $connection->table('auth_attempts')
                ->where('expires_at', '<=', $now)
                ->delete();
            $sessions = $connection->table('auth_sessions')
                ->whereNotNull('revoked_at')
                ->where('revoked_at', '<=', $sessionCutoff)
                ->delete();
            $counters = $connection->table('auth_throttle_counters')
                ->where('updated_at', '<=', $scalarCutoff)
                ->delete();
            $locks = $connection->table('auth_throttle_locks')
                ->where('locked_until', '<=', $now)
                ->where('updated_at', '<=', $scalarCutoff)
                ->delete();
            $tuples = $connection->table('auth_throttle_tuples')
                ->where('window_started_at', '<=', $tupleCutoff)
                ->delete();
            $deliveryReservations = $connection->table('auth_delivery_spend_reservations')
                ->where('window_started_at', '<', $currentDeliveryWindow)
                ->whereNotExists(function ($query): void {
                    $query->selectRaw('1')
                        ->from('auth_challenge_outbox AS pending_outbox')
                        ->whereColumn(
                            'pending_outbox.opaque_id',
                            'auth_delivery_spend_reservations.reservation_key',
                        )
                        ->where('pending_outbox.status', OtpOutboxStatus::Pending->value);
                })
                ->delete();

            return new PruneResult(
                attempts: $attempts,
                challenges: $challenges,
                revokedSessions: $sessions,
                throttleCounters: $counters,
                expiredLocks: $locks,
                tupleMarkers: $tuples,
                deliveredOutbox: $deliveredOutbox,
                undeliveredOutbox: $undeliveredOutbox,
                deliveryReservations: $deliveryReservations,
                reclaimedTokenAssurances: 0,
                retainedTokenAssurances: 0,
                unsupportedTokenAssurances: 0,
                erroredTokenAssurances: 0,
                tokenAssuranceSweepErrors: [],
                unsupportedTokenAssuranceIssuers: [],
            );
        });
    }
}
