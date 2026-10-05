<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use DateInterval;
use DateTimeImmutable;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\DurationBounds;
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

    protected $description = 'Prune expired Vouch security state and classify delivery health.';

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
            deliveredVerificationOutbox: $result->deliveredVerificationOutbox,
            undeliveredVerificationOutbox: $result->undeliveredVerificationOutbox,
            deliveredRecoveryOutbox: $result->deliveredRecoveryOutbox,
            undeliveredRecoveryOutbox: $result->undeliveredRecoveryOutbox,
            identifierVerifications: $result->identifierVerifications,
            recoveryProofs: $result->recoveryProofs,
            linkRequests: $result->linkRequests,
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
            'Pruned %d delivered and %d expired-undelivered identifier verification outbox row(s), '
            . '%d delivered and %d expired-undelivered recovery proof outbox row(s), '
            . '%d identifier verification(s), %d recovery proof(s), and %d link request(s).',
            $result->deliveredVerificationOutbox,
            $result->undeliveredVerificationOutbox,
            $result->deliveredRecoveryOutbox,
            $result->undeliveredRecoveryOutbox,
            $result->identifierVerifications,
            $result->recoveryProofs,
            $result->linkRequests,
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
            foreach ([
                'OTP' => $result->undeliveredOutbox,
                'identifier verification' => $result->undeliveredVerificationOutbox,
                'recovery proof' => $result->undeliveredRecoveryOutbox,
            ] as $kind => $count) {
                if ($count > 0) {
                    $this->components->warn(sprintf(
                        'Found %d expired undelivered %s delivery row(s). Pruning succeeded; '
                        . 'route this alert to delivery-worker health.',
                        $count,
                        $kind,
                    ));
                }
            }

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
            // Prune reads mutable config and cached throttle state after boot;
            // its cutoffs bypass deadline(). Check this database snapshot before
            // DateInterval sees the value, retaining DAYS for session retention.
            DurationBounds::backwardDays($retentionDays, 'vouch.sessions.revocation_retention_days', $now);
            DurationBounds::backward($throttle->retentionSeconds, 'vouch.throttle.retention_seconds', $now);
            DurationBounds::backward($throttle->windowSeconds, 'vouch.throttle.window_seconds', $now);
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
             * Classify every outbox before any parent cascade can delete it.
             * One database timestamp decides both classification and deletion,
             * so crossing a deadline mid-sweep cannot change the counted set.
             */
            $otpOutbox = $this->pruneOutbox($connection, 'auth_challenge_outbox', $now);
            $verificationOutbox = $this->pruneOutbox($connection, 'auth_identifier_verification_outbox', $now);
            $recoveryOutbox = $this->pruneOutbox($connection, 'auth_recovery_proof_outbox', $now);

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
            /*
             * Expired proofs already fail the redemption queries' database-clock
             * predicate; removing them cannot make a refused code usable. Link
             * requests carry no durable login authority: completed ownership is
             * on the federated identity. Verified bindings and recovery grace
             * likewise live on identifiers and sessions, which these deletes do
             * not touch. Expiry alone reclaims the ceremony, never its outcome.
             */
            $identifierVerifications = $connection->table('auth_identifier_verifications')
                ->where('expires_at', '<=', $now)
                ->delete();
            $recoveryProofs = $connection->table('auth_recovery_proofs')
                ->where('expires_at', '<=', $now)
                ->delete();
            $linkRequests = $connection->table('auth_link_requests')
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
                deliveredOutbox: $otpOutbox['delivered'],
                undeliveredOutbox: $otpOutbox['undelivered'],
                deliveredVerificationOutbox: $verificationOutbox['delivered'],
                undeliveredVerificationOutbox: $verificationOutbox['undelivered'],
                deliveredRecoveryOutbox: $recoveryOutbox['delivered'],
                undeliveredRecoveryOutbox: $recoveryOutbox['undelivered'],
                identifierVerifications: $identifierVerifications,
                recoveryProofs: $recoveryProofs,
                linkRequests: $linkRequests,
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

    /**
     * Retain the OTP reclaimer's locked classification for every delivery kind.
     * The caller holds the transaction through all parent deletes, so a worker
     * cannot change a selected status between classification and reclamation.
     *
     * @param 'auth_challenge_outbox'|'auth_identifier_verification_outbox'|'auth_recovery_proof_outbox' $table
     * @return array{delivered: int, undelivered: int}
     */
    private function pruneOutbox(Connection $connection, string $table, DateTimeImmutable $now): array
    {
        $expiredOutboxes = $connection->table($table)
            ->where('expires_at', '<=', $now)
            ->lockForUpdate()
            ->get(['id', 'status']);
        $outboxIds = [];
        $delivered = 0;
        $undelivered = 0;

        foreach ($expiredOutboxes as $row) {
            $attributes = (array) $row;
            $id = $attributes['id'] ?? null;
            $status = $attributes['status'] ?? null;

            if (! is_int($id) || ! is_string($status)) {
                throw new RuntimeException(sprintf('The database returned an invalid %s row.', $table));
            }

            $outboxIds[] = $id;

            if ($status === OtpOutboxStatus::Delivered->value) {
                $delivered++;
            } else {
                $undelivered++;
            }
        }

        if ($outboxIds !== []) {
            $connection->table($table)->whereIn('id', $outboxIds)->delete();
        }

        return ['delivered' => $delivered, 'undelivered' => $undelivered];
    }
}
