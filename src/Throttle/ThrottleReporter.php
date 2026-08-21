<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use DateInterval;
use DateTimeImmutable;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use RuntimeException;

/** Aggregate-only operational view of current throttle and OTP-delivery state. */
final readonly class ThrottleReporter
{
    public function __construct(
        private Connection $connection,
        private DatabaseTime $time,
        private ThrottleConfiguration $configuration,
    ) {}

    /**
     * @return array{
     *   generated_at: string,
     *   window_seconds: int,
     *   dimensions: list<array{
     *     dimension: string,
     *     active_buckets: int,
     *     distribution: array{zero: int, one: int, two_to_four: int, five_to_nine: int, ten_to_twenty_nine: int, thirty_to_ninety_nine: int, one_hundred_to_two_hundred_ninety_nine: int, three_hundred_plus: int},
     *     thresholds: list<array{name: string, value: int, buckets_at_or_above: int}>
     *   }>,
     *   outbox: array{pending: int, overdue: int, delivered: int, undeliverable: int, undeliverable_reasons: array<string, int>},
     *   economics: array{current_scopes: int, spent_minor: int, reservations: array{records: int, gross_minor: int, released_minor: int, unreleased_minor: int, delivered: int, attempted_failed: int, never_attempted_released: int, missing_outbox: int}}
     * }
     */
    public function report(): array
    {
        $now = $this->time->current();
        $windowCutoff = $now->sub(new DateInterval(sprintf(
            'PT%dS',
            $this->configuration->windowSeconds,
        )));

        return [
            'generated_at' => $now->format(DATE_ATOM),
            'window_seconds' => $this->configuration->windowSeconds,
            'dimensions' => [
                $this->scalar(
                    ThrottleDimension::Identifier,
                    $windowCutoff,
                    [
                        'backoff' => $this->configuration->backoffAfter,
                        'lock' => $this->configuration->lockAfter,
                    ],
                ),
                $this->scalar(
                    ThrottleDimension::Recovery,
                    $windowCutoff,
                    ['backoff' => $this->configuration->backoffAfter],
                ),
                $this->scalar(
                    ThrottleDimension::Issuance,
                    $windowCutoff,
                    ['limit' => $this->configuration->issuancesPerIdentifier],
                ),
                $this->ip(
                    ThrottleDimension::IpV4,
                    $windowCutoff,
                    ['observe' => $this->configuration->ipv4ObserveAt],
                ),
                $this->ip(
                    ThrottleDimension::IpV6,
                    $windowCutoff,
                    ['observe' => $this->configuration->ipv6ObserveAt],
                ),
                $this->scalar(
                    ThrottleDimension::Tenant,
                    $windowCutoff,
                    $this->optionalThreshold('enforce', $this->configuration->tenantEnforceAt),
                ),
                $this->scalar(
                    ThrottleDimension::Global,
                    $windowCutoff,
                    $this->optionalThreshold('enforce', $this->configuration->globalEnforceAt),
                ),
            ],
            'outbox' => $this->outbox($now),
            'economics' => $this->economics($now),
        ];
    }

    /** @return array{current_scopes: int, spent_minor: int, reservations: array{records: int, gross_minor: int, released_minor: int, unreleased_minor: int, delivered: int, attempted_failed: int, never_attempted_released: int, missing_outbox: int}} */
    private function economics(DateTimeImmutable $now): array
    {
        $today = $now->format('Y-m-d');
        $spend = $this->connection->table('auth_delivery_spend')
            ->where('window_started_at', '>=', $today . ' 00:00:00')
            ->get(['spent_minor']);
        $currentScopes = $spend->count();
        $spentMinor = 0;

        foreach ($spend as $row) {
            $spentMinor += $this->integer($row->spent_minor ?? null);
        }

        $reservations = $this->connection->table('auth_delivery_spend_reservations AS reservations')
            ->leftJoin('auth_challenge_outbox AS outbox', 'outbox.opaque_id', '=', 'reservations.reservation_key')
            ->where('reservations.window_started_at', '>=', $today . ' 00:00:00')
            ->get([
                'reservations.amount_minor',
                'reservations.released_at',
                'reservations.window_started_at',
                'outbox.status AS outbox_status',
                'outbox.provider_attempted_at',
            ]);
        $grossMinor = 0;
        $releasedMinor = 0;
        $delivered = 0;
        $attemptedFailed = 0;
        $neverAttemptedReleased = 0;
        $missingOutbox = 0;

        foreach ($reservations as $reservation) {
            $amount = $this->integer($reservation->amount_minor ?? null);
            $grossMinor += $amount;
            $released = $reservation->released_at !== null;

            if ($released) {
                $releasedMinor += $amount;
            }

            if ($reservation->outbox_status === null) {
                $missingOutbox++;
            } elseif ($reservation->outbox_status === OtpOutboxStatus::Delivered->value) {
                $delivered++;
            } elseif (
                $reservation->outbox_status === OtpOutboxStatus::Undeliverable->value
                && $reservation->provider_attempted_at !== null
            ) {
                $attemptedFailed++;
            } elseif ($released && $reservation->provider_attempted_at === null) {
                $neverAttemptedReleased++;
            }

        }

        return [
            'current_scopes' => $currentScopes,
            'spent_minor' => $spentMinor,
            'reservations' => [
                'records' => $reservations->count(),
                'gross_minor' => $grossMinor,
                'released_minor' => $releasedMinor,
                'unreleased_minor' => $grossMinor - $releasedMinor,
                'delivered' => $delivered,
                'attempted_failed' => $attemptedFailed,
                'never_attempted_released' => $neverAttemptedReleased,
                'missing_outbox' => $missingOutbox,
            ],
        ];
    }

    /**
     * @param array<string, int> $thresholds
     * @return array{dimension: string, active_buckets: int, distribution: array{zero: int, one: int, two_to_four: int, five_to_nine: int, ten_to_twenty_nine: int, thirty_to_ninety_nine: int, one_hundred_to_two_hundred_ninety_nine: int, three_hundred_plus: int}, thresholds: list<array{name: string, value: int, buckets_at_or_above: int}>}
     */
    private function scalar(
        ThrottleDimension $dimension,
        DateTimeImmutable $windowCutoff,
        array $thresholds,
    ): array {
        $base = $this->connection->table('auth_throttle_counters')
            ->where('dimension', $dimension->value)
            ->where('window_started_at', '>', $windowCutoff)
            ->select('count AS bucket_count');

        return $this->aggregate($dimension, $base, $thresholds);
    }

    /**
     * @param array<string, int> $thresholds
     * @return array{dimension: string, active_buckets: int, distribution: array{zero: int, one: int, two_to_four: int, five_to_nine: int, ten_to_twenty_nine: int, thirty_to_ninety_nine: int, one_hundred_to_two_hundred_ninety_nine: int, three_hundred_plus: int}, thresholds: list<array{name: string, value: int, buckets_at_or_above: int}>}
     */
    private function ip(
        ThrottleDimension $dimension,
        DateTimeImmutable $windowCutoff,
        array $thresholds,
    ): array {
        $tupleCounts = $this->connection->table('auth_throttle_tuples')
            ->select(['ip_window_id', 'window_started_at'])
            ->selectRaw('COUNT(*) AS bucket_count')
            ->groupBy('ip_window_id', 'window_started_at');

        $base = $this->connection->table('auth_throttle_ip_windows AS ip')
            ->leftJoinSub($tupleCounts, 'tuples', function ($join): void {
                $join->on('tuples.ip_window_id', '=', 'ip.id')
                    ->on('tuples.window_started_at', '=', 'ip.window_started_at');
            })
            ->where('ip.dimension', $dimension->value)
            ->where('ip.window_started_at', '>', $windowCutoff)
            ->selectRaw('COALESCE(tuples.bucket_count, 0) AS bucket_count');

        return $this->aggregate($dimension, $base, $thresholds);
    }

    /**
     * @param array<string, int> $thresholds
     * @return array{dimension: string, active_buckets: int, distribution: array{zero: int, one: int, two_to_four: int, five_to_nine: int, ten_to_twenty_nine: int, thirty_to_ninety_nine: int, one_hundred_to_two_hundred_ninety_nine: int, three_hundred_plus: int}, thresholds: list<array{name: string, value: int, buckets_at_or_above: int}>}
     */
    private function aggregate(
        ThrottleDimension $dimension,
        Builder $base,
        array $thresholds,
    ): array {
        $row = $this->connection->query()
            ->fromSub(clone $base, 'active_buckets')
            ->selectRaw('COUNT(*) AS active_buckets')
            ->selectRaw('SUM(CASE WHEN bucket_count = 0 THEN 1 ELSE 0 END) AS band_zero')
            ->selectRaw('SUM(CASE WHEN bucket_count = 1 THEN 1 ELSE 0 END) AS band_one')
            ->selectRaw('SUM(CASE WHEN bucket_count BETWEEN 2 AND 4 THEN 1 ELSE 0 END) AS band_two_to_four')
            ->selectRaw('SUM(CASE WHEN bucket_count BETWEEN 5 AND 9 THEN 1 ELSE 0 END) AS band_five_to_nine')
            ->selectRaw('SUM(CASE WHEN bucket_count BETWEEN 10 AND 29 THEN 1 ELSE 0 END) AS band_ten_to_twenty_nine')
            ->selectRaw('SUM(CASE WHEN bucket_count BETWEEN 30 AND 99 THEN 1 ELSE 0 END) AS band_thirty_to_ninety_nine')
            ->selectRaw('SUM(CASE WHEN bucket_count BETWEEN 100 AND 299 THEN 1 ELSE 0 END) AS band_one_hundred_to_two_hundred_ninety_nine')
            ->selectRaw('SUM(CASE WHEN bucket_count >= 300 THEN 1 ELSE 0 END) AS band_three_hundred_plus')
            ->first();

        if ($row === null) {
            throw new RuntimeException('The database returned no throttle aggregate row.');
        }

        $values = (array) $row;
        $reportedThresholds = [];

        foreach ($thresholds as $name => $value) {
            $reportedThresholds[] = [
                'name' => $name,
                'value' => $value,
                'buckets_at_or_above' => $this->connection->query()
                    ->fromSub(clone $base, 'threshold_buckets')
                    ->where('bucket_count', '>=', $value)
                    ->count(),
            ];
        }

        return [
            'dimension' => $dimension->value,
            'active_buckets' => $this->integer($values['active_buckets'] ?? null),
            'distribution' => [
                'zero' => $this->integer($values['band_zero'] ?? null),
                'one' => $this->integer($values['band_one'] ?? null),
                'two_to_four' => $this->integer($values['band_two_to_four'] ?? null),
                'five_to_nine' => $this->integer($values['band_five_to_nine'] ?? null),
                'ten_to_twenty_nine' => $this->integer($values['band_ten_to_twenty_nine'] ?? null),
                'thirty_to_ninety_nine' => $this->integer($values['band_thirty_to_ninety_nine'] ?? null),
                'one_hundred_to_two_hundred_ninety_nine' => $this->integer(
                    $values['band_one_hundred_to_two_hundred_ninety_nine'] ?? null,
                ),
                'three_hundred_plus' => $this->integer($values['band_three_hundred_plus'] ?? null),
            ],
            'thresholds' => $reportedThresholds,
        ];
    }

    /** @return array{pending: int, overdue: int, delivered: int, undeliverable: int, undeliverable_reasons: array<string, int>} */
    private function outbox(DateTimeImmutable $now): array
    {
        $outbox = $this->connection->table('auth_challenge_outbox');

        $reasons = [];

        foreach ((clone $outbox)
            ->where('status', OtpOutboxStatus::Undeliverable->value)
            ->selectRaw('failure_reason, COUNT(*) AS reason_count')
            ->groupBy('failure_reason')
            ->get() as $row) {
            $reason = is_string($row->failure_reason) && $row->failure_reason !== ''
                ? $row->failure_reason
                : 'unknown';
            $reasons[$reason] = $this->integer($row->reason_count ?? null);
        }

        ksort($reasons);

        return [
            'pending' => (clone $outbox)
                ->where('status', OtpOutboxStatus::Pending->value)
                ->where('expires_at', '>', $now)
                ->count(),
            'overdue' => (clone $outbox)
                ->where('status', OtpOutboxStatus::Pending->value)
                ->where('expires_at', '<=', $now)
                ->count(),
            'delivered' => (clone $outbox)
                ->where('status', OtpOutboxStatus::Delivered->value)
                ->count(),
            'undeliverable' => (clone $outbox)
                ->where('status', OtpOutboxStatus::Undeliverable->value)
                ->count(),
            'undeliverable_reasons' => $reasons,
        ];
    }

    /** @return array<string, int> */
    private function optionalThreshold(string $name, ?int $value): array
    {
        return $value === null ? [] : [$name => $value];
    }

    private function integer(mixed $value): int
    {
        if ($value === null) {
            return 0;
        }

        if (is_int($value)) {
            return $value;
        }

        if (is_string($value) && preg_match('/^(?:0|[1-9][0-9]*)$/D', $value) === 1) {
            $integer = filter_var($value, FILTER_VALIDATE_INT);

            if (is_int($integer)) {
                return $integer;
            }
        }

        throw new RuntimeException('The database returned an invalid aggregate count.');
    }
}
