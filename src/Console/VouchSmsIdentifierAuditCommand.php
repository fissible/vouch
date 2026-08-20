<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Fissible\Vouch\Delivery\SmsIdentifierAudit;
use Illuminate\Console\Command;
use JsonException;

/**
 * Reports legacy SMS rows without mutating or printing identifier values.
 * Invalid rows are survey results, not command failure; this command always
 * exits successfully unless the audit itself throws.
 */
final class VouchSmsIdentifierAuditCommand extends Command
{
    protected $signature = 'vouch:sms-identifiers:audit {--json : Emit machine-readable aggregate JSON}';

    protected $description = 'Audit stored SMS identifiers before canonicalization.';

    /** @throws JsonException */
    public function handle(SmsIdentifierAudit $audit): int
    {
        $report = $audit->report();

        if ($this->option('json') === true) {
            $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));

            return CommandExit::Success->value;
        }

        $this->table(
            ['Total', 'Canonical', 'Needs normalization', 'Invalid'],
            [[
                $report['total'],
                $report['canonical'],
                $report['needs_normalization'],
                $report['invalid'],
            ]],
        );

        $this->components->info('Country counts: ' . json_encode($report['countries'], JSON_THROW_ON_ERROR));

        return CommandExit::Success->value;
    }
}
