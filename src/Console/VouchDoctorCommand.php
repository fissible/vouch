<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Contracts\CaptchaVerifier;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Delivery\UnconfiguredCaptchaVerifier;
use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\MalformedEvidence;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Delivery\UnconfiguredDeliveryEconomics;
use Illuminate\Console\Command;
use Illuminate\Database\ConnectionInterface;
use JsonException;
use Throwable;

/** Reports aggregate adoption prerequisites without inspecting any account. */
final class VouchDoctorCommand extends Command
{
    protected $signature = 'vouch:doctor {--json : Emit machine-readable aggregate JSON}';

    protected $description = 'Check Vouch adoption prerequisites.';

    /** @throws JsonException */
    public function handle(
        OtpQueueDispatcher $dispatcher,
        ThrottleConfiguration $throttle,
        ConnectionInterface $connection,
        AssuranceVocabulary $vocabulary,
        TokenAssuranceRecord $tokenAssurances,
    ): int {
        try {
            $totalIdentifiers = AuthIdentifier::query()->count();
            $verifiedIdentifiers = AuthIdentifier::query()->whereNotNull('verified_at')->count();
            $rows = [
                [
                    'prerequisite' => 'verified_at',
                    'status' => $totalIdentifiers > 0 && $verifiedIdentifiers === 0 ? 'missing' : 'pass',
                    'total_identifiers' => $totalIdentifiers,
                    'verified_identifiers' => $verifiedIdentifiers,
                ],
                ['prerequisite' => 'OtpDelivery', 'status' => $this->deliveryStatus()],
                ['prerequisite' => 'durable_queue', 'status' => $this->queueStatus($dispatcher)],
                ['prerequisite' => 'DeliveryEconomics', 'status' => $this->economicsStatus()],
            ];

            if ($throttle->captchaEnabled) {
                $rows[] = [
                    'prerequisite' => 'CaptchaVerifier',
                    'status' => $this->captchaStatus(),
                ];
            }

            $missing = count(array_filter(
                $rows,
                static fn (array $row): bool => $row['status'] === 'missing',
            ));

            $driftTables = [
                $this->scanSessions($connection, $vocabulary),
                $tokenAssurances->driftCounts($this->driftBatch()),
            ];
            $report = [
                'missing' => $missing,
                'prerequisites' => $rows,
                'acr_drift' => [
                    'status' => array_any($driftTables, static fn (array $table): bool => $table['drifted'] > 0) ? 'drift' : 'pass',
                    'tables' => $driftTables,
                ],
            ];

            if ($this->option('json') === true) {
                $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
            } else {
                $this->table(['Prerequisite', 'Status', 'Details'], array_map(
                    static fn (array $row): array => [
                        $row['prerequisite'],
                        $row['status'],
                        isset($row['total_identifiers'])
                            ? sprintf('%d total, %d verified', $row['total_identifiers'], $row['verified_identifiers'])
                            : '',
                    ],
                    $rows,
                ));
                $this->table(['Table', 'Checked', 'Drifted', 'Unreadable'], array_map(
                    static fn (array $table): array => [
                        $table['table'],
                        $table['checked'],
                        $table['drifted'],
                        $table['unreadable'],
                    ],
                    $driftTables,
                ));
            }

            return $missing === 0
                ? CommandExit::Success->value
                : CommandExit::Failure->value;
        } catch (Throwable $exception) {
            $this->components->error('Vouch doctor could not complete: ' . $exception->getMessage());

            // 2 is diagnostic failure here; CommandExit::DeliveryHealth uses
            // the same integer for vouch:prune's distinct domain signal.
            return 2;
        }
    }

    private function deliveryStatus(): string
    {
        return app(OtpDelivery::class) instanceof UnconfiguredOtpDelivery ? 'missing' : 'pass';
    }

    private function economicsStatus(): string
    {
        return app(DeliveryEconomics::class) instanceof UnconfiguredDeliveryEconomics ? 'missing' : 'pass';
    }

    private function captchaStatus(): string
    {
        return app(CaptchaVerifier::class) instanceof UnconfiguredCaptchaVerifier ? 'missing' : 'pass';
    }

    private function queueStatus(OtpQueueDispatcher $dispatcher): string
    {
        try {
            $dispatcher->assertAsynchronous();

            return 'pass';
        } catch (Throwable) {
            return 'missing';
        }
    }

    /** @return array{table:string,checked:int,drifted:int,unreadable:int} */
    private function scanSessions(ConnectionInterface $connection, AssuranceVocabulary $vocabulary): array
    {
        $counts = ['table' => 'auth_sessions', 'checked' => 0, 'drifted' => 0, 'unreadable' => 0];

        foreach ($connection->table('auth_sessions')->orderBy('id')->lazyById($this->driftBatch(), 'id') as $row) {
            if ($row->assurance_proof === null) {
                continue;
            }

            $counts['checked']++;
            $evidence = $this->evidence($row->assurance_proof);
            if ($evidence === null || $row->acr === null) {
                $counts['unreadable']++;

                continue;
            }
            if ($row->acr !== $vocabulary->name($evidence->facts())) {
                $counts['drifted']++;
            }
        }

        return $counts;
    }

    private function driftBatch(): int
    {
        return max(1, config()->integer('vouch.doctor.drift_batch', 500));
    }

    private function evidence(mixed $proof): ?AssuranceEvidence
    {
        try {
            if (is_string($proof)) {
                $proof = json_decode($proof, true, 512, JSON_THROW_ON_ERROR);
            }
            if (! is_array($proof)) {
                return null;
            }

            return AssuranceEvidence::fromArray($proof);
        } catch (JsonException|MalformedEvidence) {
            return null;
        }
    }

}
