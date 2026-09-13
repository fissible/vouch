<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Illuminate\Support\Facades\DB;

/**
 * Samples one proof row BETWEEN statements, so a two-step burn is visible.
 *
 * Final state cannot distinguish one statement from two. An implementation that
 * increments attempts and stamps burned_at in separate statements leaves a
 * window where the two disagree, and sampling before each query catches it,
 * because the second statement passes through the same seam.
 *
 * WHAT THIS IS NOT. It sees statements routed through ONE connection, so it
 * detects a split write rather than proving a single one: an intermediate state
 * visible here may be invisible to a competing writer inside a transaction, and
 * nothing here counts burn transitions. Literal same-write and exactly-once
 * transition coverage remain open.
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
     * Samples where the count and the burn disagree.
     *
     * BOTH orderings, because a split write can go either way: increment then
     * burn leaves the row at the limit and unburned, while burn then increment
     * leaves it burned while still short of the limit. Checking only the first
     * lets the second through, which was measured passing the whole suite.
     *
     * @return list<array{attempts: int, burned: bool}>
     */
    public function inconsistentSamples(int $limit): array
    {
        return array_values(array_filter(
            $this->seen,
            static fn (array $state): bool => ($state['attempts'] >= $limit && $state['burned'] === false)
                || ($state['burned'] === true && $state['attempts'] < $limit),
        ));
    }
}
