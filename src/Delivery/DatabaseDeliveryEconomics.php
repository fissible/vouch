<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\LockContention;
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
    ) {}

    public function preflight(DeliveryEconomicsRequest $request): DeliveryEconomicsDecision
    {
        // Country and spend are deliberately worker-side decisions. This call
        // must not resolve a target or create a read/write asymmetry for decoys.
        return DeliveryEconomicsDecision::Permitted;
    }

    public function reserve(DeliveryEconomicsRequest $request): DeliveryEconomicsDecision
    {
        if ($request->decoy) {
            return DeliveryEconomicsDecision::Permitted;
        }

        if ($request->channel === 'sms'
            && ($request->country === null
                || ! in_array($request->country, $this->configuration->smsAllowedCountries, true))) {
            return DeliveryEconomicsDecision::Refused;
        }

        if ($request->costMinor === 0
            || ($this->configuration->dailyCeilingMinor === null
                && $this->configuration->tenantCeilingMinor === null)) {
            return DeliveryEconomicsDecision::Permitted;
        }

        try {
            return $this->boundedLockWait->shared(
                fn (): DeliveryEconomicsDecision => $this->connection->transaction(
                    fn (): DeliveryEconomicsDecision => $this->reserveAtomically($request),
                ),
            );
        } catch (DeliverySpendRefused) {
            return DeliveryEconomicsDecision::Refused;
        } catch (QueryException $exception) {
            if ($this->lockContention->isVerified($this->connection, $exception)) {
                // Economics is delivery-facing and not an authentication
                // authority. Contention refuses this send rather than parking
                // a worker or allowing an unbounded spend race.
                return DeliveryEconomicsDecision::Refused;
            }

            throw $exception;
        }
    }

    private function reserveAtomically(DeliveryEconomicsRequest $request): DeliveryEconomicsDecision
    {
        $scopes = [];

        if ($this->configuration->dailyCeilingMinor !== null) {
            $scopes[] = [self::GLOBAL, $this->keys->global()->digest, $this->configuration->dailyCeilingMinor];
        }

        if ($this->configuration->tenantCeilingMinor !== null) {
            $scopes[] = [self::TENANT, $this->keys->tenant($request->tenantId)->digest, $this->configuration->tenantCeilingMinor];
        }

        foreach ($scopes as [$scope, $digest, $ceiling]) {
            $this->ensureRow((string) $scope, (string) $digest);
            $row = $this->row((string) $scope, (string) $digest, true);

            if ($row === null) {
                throw new \RuntimeException('The delivery spend row vanished after creation.');
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

            $updated = $this->connection->table('auth_delivery_spend')
                ->where('id', $row['id'])
                ->where('spent_minor', '<=', (int) $ceiling - $request->costMinor)
                ->increment('spent_minor', $request->costMinor, ['updated_at' => $this->time->now()]);

            if ($updated !== 1) {
                throw new DeliverySpendRefused();
            }
        }

        return DeliveryEconomicsDecision::Permitted;
    }

    private function ensureRow(string $scope, string $digest): void
    {
        $now = $this->time->now();
        $this->connection->table('auth_delivery_spend')->insertOrIgnore([
            'scope' => $scope,
            'subject_digest' => $digest,
            'window_started_at' => $this->time->current()->format('Y-m-d 00:00:00'),
            'spent_minor' => 0,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
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
