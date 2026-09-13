<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Illuminate\Support\Facades\DB;

/**
 * Samples one proof row BETWEEN statements, so a two-step burn is visible.
 *
 * Final state cannot distinguish one statement from two. An implementation that
 * increments attempts, returns to PHP, then stamps burned_at separately leaves a
 * window where the row reads at-the-limit and unburned -- and in that window
 * another guess still counts. Sampling before each query catches exactly that,
 * because the second statement has to pass through the same seam.
 *
 * The re-entrancy flag lives on the object rather than in a closure variable:
 * the sampler issues a query of its own, which would otherwise sample itself
 * forever.
 */
final class ProofStateObserver
{
    /** @var list<array{attempts: int, burned: bool}> */
    public array $seen = [];

    private bool $inspecting = false;

    public function __construct(
        private readonly string $table,
        private readonly int $id,
    ) {}

    public function observe(): void
    {
        if ($this->inspecting) {
            return;
        }

        $this->inspecting = true;

        try {
            $row = DB::table($this->table)->where('id', $this->id)->first(['attempts', 'burned_at']);

            if (is_object($row) && property_exists($row, 'attempts')) {
                $attempts = $row->attempts;
                $burned = property_exists($row, 'burned_at') ? $row->burned_at : null;

                $this->seen[] = [
                    'attempts' => is_scalar($attempts) ? (int) $attempts : 0,
                    'burned' => $burned !== null,
                ];
            }
        } finally {
            $this->inspecting = false;
        }
    }

    /**
     * Samples showing the row at or past the limit while still unburned.
     *
     * @return list<array{attempts: int, burned: bool}>
     */
    public function atLimitUnburned(int $limit): array
    {
        return array_values(array_filter(
            $this->seen,
            static fn (array $state): bool => $state['attempts'] >= $limit && $state['burned'] === false,
        ));
    }
}
