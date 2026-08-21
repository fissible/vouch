<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Support\DatabaseRowLock;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Database\Connection;
use Illuminate\Database\QueryException;

/**
 * Delivery-side country policy and atomic spend reservation.
 *
 * The request-side preflight is intentionally advisory. `reserve()` is the
 * only writer and checks both ceilings while holding the spend rows, so a
 * burst cannot overspend merely because several workers passed the preflight.
 */
final readonly class DatabaseDeliveryEconomics implements DeliveryEconomics
{
    private const string GLOBAL = 'global';

    private const string TENANT = 'tenant';

    public function __construct(
        private Connection $connection,
        private DatabaseTime $time,
        private ThrottleKey $keys,
        private DeliveryEconomicsConfiguration $configuration,
        private BoundedLockWait $boundedLockWait,
        private LockContention $lockContention,
        ?DatabaseRowLock $rowLock = null,
    ) {
        $this->rowLock = $rowLock ?? new DatabaseRowLock($connection);
    }

    private readonly DatabaseRowLock $rowLock;

    public function preflight(DeliveryEconomicsRequest $request): DeliveryEconomicsDecision
    {
        // Country and spend are deliberately worker-side decisions. This call
        // must not resolve a target or create a read/write asymmetry for decoys.
        return DeliveryEconomicsDecision::Permitted;
    }

    public function reserve(DeliveryEconomicsRequest $request): DeliveryReservationDecision
    {
        if ($request->decoy) {
            return DeliveryReservationDecision::Permitted;
        }

        if ($request->channel === 'sms'
            && ($request->country === null
                || ! in_array($request->country, $this->configuration->smsAllowedCountries, true))) {
            return DeliveryReservationDecision::CountryNotAllowed;
        }

        if ($request->costMinor === 0) {
            return DeliveryReservationDecision::Permitted;
        }

        try {
            return $this->boundedLockWait->shared(
                fn (): DeliveryReservationDecision => $this->connection->transaction(
                    fn (): DeliveryReservationDecision => $this->reserveAtomically($request),
                ),
            );
        } catch (DeliverySpendRefused) {
            return DeliveryReservationDecision::SpendCeiling;
        } catch (QueryException $exception) {
            if ($this->lockContention->isVerified($this->connection, $exception)) {
                // Economics is delivery-facing and not an authentication
                // authority. Contention refuses this send rather than parking
                // a worker or allowing an unbounded spend race.
                return DeliveryReservationDecision::RetryableContention;
            }

            throw $exception;
        }
    }

    public function release(DeliveryEconomicsRequest $request): void
    {
        if ($request->decoy || $request->costMinor === 0 || $request->reservationKey === null || $request->reservationKey === '') {
            return;
        }

        $this->connection->transaction(function () use ($request): void {
            foreach ([
                [self::GLOBAL, $this->keys->global()->digest],
                [self::TENANT, $this->keys->tenant($request->tenantId)->digest],
            ] as [$scope, $digest]) {
                $row = $this->row((string) $scope, (string) $digest, true);

                if ($row === null) {
                    throw new \RuntimeException('The delivery spend row vanished during release.');
                }

                $reservation = $this->connection->table('auth_delivery_spend_reservations')
                    ->where('reservation_key', $request->reservationKey)
                    ->where('scope', (string) $scope)
                    ->lockForUpdate()
                    ->first();

                if ($reservation === null) {
                    continue;
                }

                if ($reservation->released_at !== null) {
                    continue;
                }

                if ((string) $reservation->window_started_at !== $row['window_started_at']) {
                    $this->connection->table('auth_delivery_spend_reservations')
                        ->where('id', $reservation->id)
                        ->update(['released_at' => $this->time->now()]);

                    continue;
                }

                $value = $reservation->amount_minor;

                if (! is_int($value) && ! is_string($value)) {
                    throw new \RuntimeException('The delivery reservation amount has an invalid type.');
                }

                $amount = (int) $value;
                $updated = $this->connection->table('auth_delivery_spend')
                    ->where('id', $row['id'])
                    ->where('spent_minor', '>=', $amount)
                    ->decrement('spent_minor', $amount, ['updated_at' => $this->time->now()]);

                if ($updated !== 1) {
                    $this->connection->table('auth_delivery_spend_reservations')
                        ->where('id', $reservation->id)
                        ->update(['released_at' => $this->time->now()]);

                    continue;
                }

                $this->connection->table('auth_delivery_spend_reservations')
                    ->where('id', $reservation->id)
                    ->update(['released_at' => $this->time->now()]);
            }
        });
    }

    private function reserveAtomically(DeliveryEconomicsRequest $request): DeliveryReservationDecision
    {
        if ($request->reservationKey === null || $request->reservationKey === '') {
            throw new \InvalidArgumentException(
                'A real delivery reservation requires its opaque outbox key.',
            );
        }

        $scopes = [
            [self::GLOBAL, $this->keys->global()->digest, $this->configuration->dailyCeilingMinor],
            [self::TENANT, $this->keys->tenant($request->tenantId)->digest, $this->configuration->tenantCeilingMinor],
        ];

        foreach ($scopes as [$scope, $digest, $ceiling]) {
            $this->rowLock->ensureAndLock(
                'auth_delivery_spend',
                [
                    'scope' => (string) $scope,
                    'subject_digest' => (string) $digest,
                    'window_started_at' => $this->time->current()->format('Y-m-d 00:00:00'),
                    'spent_minor' => 0,
                    'created_at' => $this->time->now(),
                    'updated_at' => $this->time->now(),
                ],
                ['scope' => (string) $scope, 'subject_digest' => (string) $digest],
            );
            $row = $this->row((string) $scope, (string) $digest, true);

            if ($row === null) {
                throw new \RuntimeException('The delivery spend row vanished after creation.');
            }

            // The unique claim must stand on its own. Do not replace this with
            // exists() followed by insert(): the spend-row lock protects the
            // current accounting transaction, but it is not the reservation's
            // correctness boundary and may be removed for an unceilinged scope.
            $claimed = $this->connection->table('auth_delivery_spend_reservations')->insertOrIgnore([[
                'reservation_key' => $request->reservationKey,
                'scope' => (string) $scope,
                'amount_minor' => $request->costMinor,
                'window_started_at' => $this->time->current()->format('Y-m-d 00:00:00'),
                'created_at' => $this->time->now(),
            ]]);

            if ($claimed === 0) {
                continue;
            }

            $today = $this->time->current()->format('Y-m-d');
            $started = substr($row['window_started_at'], 0, 10);

            if ($started !== $today) {
                $this->connection->table('auth_delivery_spend')
                    ->where('id', $row['id'])
                    ->update([
                        'window_started_at' => $today . ' 00:00:00',
                        'spent_minor' => 0,
                        'updated_at' => $this->time->now(),
                    ]);
                $row = $this->row((string) $scope, (string) $digest, true);

                if ($row === null) {
                    throw new \RuntimeException('The delivery spend row vanished after rollover.');
                }
            }

            $update = $this->connection->table('auth_delivery_spend')
                ->where('id', $row['id']);

            if ($ceiling !== null) {
                $update->where('spent_minor', '<=', (int) $ceiling - $request->costMinor);
            }

            $updated = $update->increment(
                'spent_minor',
                $request->costMinor,
                ['updated_at' => $this->time->now()],
            );

            if ($updated !== 1) {
                if ($ceiling !== null) {
                    throw new DeliverySpendRefused();
                }

                throw new \RuntimeException('The delivery spend row vanished during accounting.');
            }

        }

        return DeliveryReservationDecision::Permitted;
    }

    /** @return array{id: int, window_started_at: string}|null */
    private function row(string $scope, string $digest, bool $lock): ?array
    {
        $query = $this->connection->table('auth_delivery_spend')
            ->where('scope', $scope)
            ->where('subject_digest', $digest);

        if ($lock) {
            $query->lockForUpdate();
        }

        $row = $query->first();

        if ($row === null) {
            return null;
        }

        $values = (array) $row;

        return [
            'id' => (int) $values['id'],
            'window_started_at' => (string) $values['window_started_at'],
        ];
    }
}
