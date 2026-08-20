<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use Fissible\Vouch\Models\AuthIdentifier;
use InvalidArgumentException;

/** Aggregate-only inventory of legacy SMS identifier rows; never rewrites data. */
final readonly class SmsIdentifierAudit
{
    public function __construct(private SmsCountryNormalizer $normalizer)
    {
    }

    /**
     * @return array{total: int, canonical: int, needs_normalization: int, invalid: int, countries: array<string, int>}
     */
    public function report(): array
    {
        $report = [
            'total' => 0,
            'canonical' => 0,
            'needs_normalization' => 0,
            'invalid' => 0,
            'countries' => [],
        ];

        foreach (AuthIdentifier::query()->where('type', 'phone')->cursor() as $identifier) {
            $report['total']++;

            try {
                $normalized = $this->normalizer->normalize($identifier->value);
            } catch (InvalidArgumentException) {
                $report['invalid']++;

                continue;
            }

            if ($normalized->e164 === $identifier->value) {
                $report['canonical']++;
            } else {
                $report['needs_normalization']++;
            }

            $report['countries'][$normalized->country] = ($report['countries'][$normalized->country] ?? 0) + 1;
        }

        ksort($report['countries']);

        return $report;
    }
}
