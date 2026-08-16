<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Throttle\ThrottleReporter;
use Illuminate\Console\Command;
use JsonException;

/** Aggregate observation only: no subject input and no per-bucket output. */
final class VouchThrottleReportCommand extends Command
{
    protected $signature = 'vouch:throttle:report {--json : Emit machine-readable aggregate JSON}';

    protected $description = 'Report aggregate Vouch throttle and OTP delivery health.';

    /** @throws JsonException */
    public function handle(ThrottleReporter $reporter): int
    {
        $report = $reporter->report();

        if ($this->option('json') === true) {
            $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

            return CommandExit::Success->value;
        }

        $rows = [];

        foreach ($report['dimensions'] as $dimension) {
            $thresholds = array_map(
                static fn (array $threshold): string => sprintf(
                    '%s=%d (%d crossed)',
                    $threshold['name'],
                    $threshold['value'],
                    $threshold['buckets_at_or_above'],
                ),
                $dimension['thresholds'],
            );

            $rows[] = [
                $dimension['dimension'],
                $dimension['active_buckets'],
                implode(', ', $thresholds) ?: 'none',
                json_encode($dimension['distribution'], JSON_THROW_ON_ERROR),
            ];
        }

        $this->table(
            ['Dimension', 'Active buckets', 'Thresholds', 'Distribution'],
            $rows,
        );
        $this->components->info(sprintf(
            'OTP outbox: %d pending, %d overdue, %d delivered, %d undeliverable.',
            $report['outbox']['pending'],
            $report['outbox']['overdue'],
            $report['outbox']['delivered'],
            $report['outbox']['undeliverable'],
        ));

        return CommandExit::Success->value;
    }
}
