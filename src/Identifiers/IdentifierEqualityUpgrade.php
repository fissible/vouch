<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\Connection;
use Illuminate\Database\Query\Builder;
use stdClass;

/**
 * #59. Identity stops being whatever collation the host happens to have installed.
 *
 * Two halves, and either alone is a regression. The identifier columns get a
 * deterministic collation so SQL equality is byte equality, and
 * IdentifierCanonicalizer's output is what gets stored -- so the only folding
 * that happens is the folding Vouch chose.
 *
 * Existing rows may disagree with that, in both directions:
 *
 *   MERGES. Two byte-distinct rows canonicalize onto one value. The unique
 *   indexes make this structurally impossible to write, so it has to be settled
 *   before the conversion rather than discovered during it.
 *
 *   SPLITS. Rows an accent-insensitive collation treated as one address
 *   canonicalize apart. Nothing breaks structurally, but credentials that were
 *   one account's are now divided between two.
 *
 * Triage, per table:
 *
 *   auth_identifiers always REFUSES. The row is the account, and nothing here
 *   can know which of two addresses owns it.
 *
 *   The proof and verification tables hold minute-scale credentials, so a
 *   collision between LIVE rows is deleted -- costing a user one re-request --
 *   and REFUSED when any row in it is consumed or burned, because #31 and #38
 *   both make those terminal states permanent records of what happened.
 *
 *   auth_proof_issuance_locks is a mutex, not a record. Two spellings claiming
 *   one scope cannot both survive unique(ceremony, type, value), so the
 *   non-canonical anchor goes and the scope keeps exactly one.
 *
 * A refusal changes NOTHING -- not a row, not a column -- so an operator who
 * reconciles the reported rows re-runs against the database they started with
 * rather than one that is already half converted.
 *
 * This lives here rather than inside the migration for a measured reason: a
 * migration file is recompiled on every migrate, and the suite runs hundreds of
 * them. At this size that cost 32 MB of never-reclaimed compiled classes across
 * one suite run and exhausted the pinned memory limit. An autoloaded class is
 * compiled once.
 */
final readonly class IdentifierEqualityUpgrade
{
    public function __construct(
        private Connection $connection,
        private IdentifierCanonicalizer $canonicalizer,
    ) {}

    /**
     * Every column that holds an identifier, and what a collision there means.
     *
     * `refuse` is an account row, `transient` a short-lived credential, `mutex`
     * a serialization anchor. `keyed` says whether rows have an id to report;
     * auth_proof_issuance_locks has none, and never needs one, because it never
     * refuses.
     */
    private const TABLES = [
        'auth_identifiers' => [
            'type' => 'type', 'value' => 'value',
            'keyed' => true, 'scope' => null, 'policy' => 'refuse',
        ],
        'auth_identifier_verifications' => [
            'type' => 'identifier_type', 'value' => 'identifier_value',
            'keyed' => true, 'scope' => null, 'policy' => 'transient',
        ],
        'auth_recovery_proofs' => [
            'type' => 'identifier_type', 'value' => 'identifier_value',
            'keyed' => true, 'scope' => null, 'policy' => 'transient',
        ],
        'auth_proof_issuance_locks' => [
            'type' => 'identifier_type', 'value' => 'identifier_value',
            'keyed' => false, 'scope' => 'ceremony', 'policy' => 'mutex',
        ],
    ];

    /** Characters each identifier column holds, as the tables declare them. */
    private const LENGTHS = ['type' => 32, 'value' => 255];

    /** Rows per statement in the rewrite. */
    private const CHUNK = 200;

    public function apply(): void
    {
        /*
         * Read every table BEFORE deciding anything, and decide everything
         * before writing anything. The refusal contract is that a refused
         * upgrade left no trace, which a table-at-a-time convert-then-check
         * cannot honour.
         */
        $scanned = [];

        foreach (self::TABLES as $table => $spec) {
            $scanned[$table] = $this->scan($table, $spec);
        }

        /** @var list<IdentifierCollision> $refusals */
        $refusals = [];
        /** @var array<string, list<int>> $doomed */
        $doomed = [];
        /** @var array<string, list<array<string, string>>> $surplus */
        $surplus = [];

        foreach (self::TABLES as $table => $spec) {
            $triage = $this->triage($table, $spec, $scanned[$table]);

            $refusals = array_merge($refusals, $triage['refusals']);
            $doomed[$table] = $triage['doomed'];
            $surplus[$table] = $triage['surplus'];
        }

        if ($refusals !== []) {
            throw new IdentifierCollisionsFound($refusals);
        }

        /*
         * Schema first, then rows. Every delete and update below names an exact
         * spelling, and only a deterministic collation makes "this spelling"
         * mean one row: under the collation being replaced, a delete aimed at
         * one anchor takes its canonical twin with it.
         */
        $this->convert();

        foreach (self::TABLES as $table => $spec) {
            $this->discard($table, $spec, $doomed[$table], $surplus[$table]);
            $this->rewrite($table, $spec, $scanned[$table], $doomed[$table], $surplus[$table]);
        }
    }

    /**
     * Every row of one identifier table, with its canonical form and the
     * equality class the column's CURRENT collation puts it in.
     *
     * The loose class is the only way a SPLIT is visible. Two rows an
     * accent-insensitive collation considers one address canonicalize apart,
     * and no amount of PHP can discover that equality -- only the engine knows
     * it. So the engine is asked, in the same statement that reads the rows,
     * via an index-backed correlated subquery rather than a query per pair.
     *
     * @param  array{type: string, value: string, keyed: bool, scope: string|null, policy: string}  $spec
     * @return list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>
     */
    private function scan(string $table, array $spec): array
    {
        $quoted = $this->quote($table);
        $type = $this->quote($spec['type']);
        $value = $this->quote($spec['value']);

        $select = [
            sprintf('t.%s as row_type', $type),
            sprintf('t.%s as row_value', $value),
        ];

        if ($spec['keyed']) {
            $select[] = 't.id as row_id';
            $select[] = sprintf(
                '(select min(o.id) from %s o where o.%s = t.%s and o.%s = t.%s) as loose_class',
                $quoted,
                $type,
                $type,
                $value,
                $value,
            );
        }

        if ($spec['scope'] !== null) {
            $select[] = sprintf('t.%s as row_scope', $this->quote($spec['scope']));
        }

        if ($spec['policy'] === 'transient') {
            $select[] = 't.consumed_at as consumed_at';
            $select[] = 't.burned_at as burned_at';
        }

        $rows = [];
        $index = 0;

        foreach ($this->connection->select(sprintf('select %s from %s t', implode(', ', $select), $quoted)) as $row) {
            if (! $row instanceof stdClass) {
                continue;
            }

            $storedType = $this->text($row, 'row_type');
            $storedValue = $this->text($row, 'row_value');
            $scope = $this->text($row, 'row_scope');
            $canonicalType = $this->canonicalizer->canonicalize($storedType);
            $canonicalValue = $this->canonicalizer->canonicalize($storedValue);

            $rows[] = [
                'id' => $spec['keyed'] ? $this->number($row, 'row_id') : null,
                'scope' => $scope,
                'type' => $storedType,
                'value' => $storedValue,
                'canonicalType' => $canonicalType,
                'canonical' => $canonicalValue,
                'key' => implode("\0", [$scope, $canonicalType, $canonicalValue]),
                /*
                 * An unkeyed table gets a class of its own per row, which is
                 * correct rather than a shortcut: unique(ceremony, type, value)
                 * means a loose collation REJECTS the second of two rows it
                 * considers equal, so a split is unconstructible there.
                 */
                'loose' => $spec['keyed'] ? (string) $this->number($row, 'loose_class') : 'row-' . $index,
                'terminal' => $this->present($row, 'consumed_at') || $this->present($row, 'burned_at'),
            ];

            $index++;
        }

        return $rows;
    }

    /**
     * What this table's collisions cost: rows to refuse over, rows to delete,
     * anchors to drop.
     *
     * @param  array{type: string, value: string, keyed: bool, scope: string|null, policy: string}  $spec
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @return array{refusals: list<IdentifierCollision>, doomed: list<int>, surplus: list<array<string, string>>}
     */
    private function triage(string $table, array $spec, array $rows): array
    {
        /** @var list<IdentifierCollision> $refusals */
        $refusals = [];
        /** @var list<int> $doomed */
        $doomed = [];
        /** @var list<array<string, string>> $surplus */
        $surplus = [];

        foreach ($this->components($rows) as $component) {
            $spellings = [];
            $terminal = false;

            foreach ($component as $position) {
                $spellings[$rows[$position]['type'] . "\0" . $rows[$position]['value']] = true;
                $terminal = $terminal || $rows[$position]['terminal'];
            }

            /*
             * One spelling is not a collision. Several rows sharing one exact
             * value is the ordinary state of a supersession chain, and deleting
             * those would destroy the history the change is supposed to leave
             * alone -- there is nothing to choose between when the bytes agree.
             */
            if (count($spellings) < 2) {
                continue;
            }

            if ($spec['policy'] === 'mutex') {
                $surplus = array_merge($surplus, $this->dropAnchors($spec, $rows, $component));

                continue;
            }

            if ($spec['policy'] === 'transient' && ! $terminal) {
                foreach ($this->ids($rows, $component) as $id) {
                    $doomed[] = $id;
                }

                continue;
            }

            /*
             * Everything else refuses: an account row, whichever way it
             * collides, and a transient one holding a consumed or burned proof.
             */
            $refusals[] = new IdentifierCollision(
                $table,
                $this->contested($rows, $component),
                $this->ids($rows, $component),
            );
        }

        return ['refusals' => $refusals, 'doomed' => $doomed, 'surplus' => $surplus];
    }

    /**
     * Rows grouped by everything that has to agree about them.
     *
     * Two relations, unioned and closed transitively: rows sharing a canonical
     * form (a merge) and rows the current collation already considers equal (a
     * split). Neither alone is enough, and a group can be reached through both
     * -- so this is a disjoint-set walk over the rows rather than a group-by on
     * either key.
     *
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @return list<list<int>> positions in $rows
     */
    private function components(array $rows): array
    {
        /** @var array<int, int> $parent */
        $parent = [];
        /** @var array<string, int> $seen */
        $seen = [];

        foreach (array_keys($rows) as $position) {
            $parent[$position] = $position;
        }

        foreach ($rows as $position => $row) {
            foreach (['canonical:' . $row['key'], 'loose:' . $row['loose']] as $key) {
                if (isset($seen[$key])) {
                    $this->fuse($parent, $seen[$key], $position);

                    continue;
                }

                $seen[$key] = $position;
            }
        }

        /** @var array<int, list<int>> $components */
        $components = [];

        foreach (array_keys($parent) as $position) {
            $components[$this->root($parent, $position)][] = $position;
        }

        return array_values($components);
    }

    /**
     * @param  array<int, int>  $parent
     */
    private function fuse(array &$parent, int $left, int $right): void
    {
        $first = $this->root($parent, $left);
        $second = $this->root($parent, $right);

        if ($first !== $second) {
            $parent[$second] = $first;
        }
    }

    /**
     * @param  array<int, int>  $parent
     */
    private function root(array &$parent, int $position): int
    {
        while ($parent[$position] !== $position) {
            $parent[$position] = $parent[$parent[$position]];
            $position = $parent[$position];
        }

        return $position;
    }

    /**
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @param  list<int>  $component
     * @return list<int>
     */
    private function ids(array $rows, array $component): array
    {
        $ids = [];

        foreach ($component as $position) {
            $id = $rows[$position]['id'];

            if ($id !== null) {
                $ids[] = $id;
            }
        }

        sort($ids);

        return $ids;
    }

    /**
     * The canonical value a colliding group contends for, taken from its
     * lowest-numbered row so the report is stable between runs.
     *
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @param  list<int>  $component
     */
    private function contested(array $rows, array $component): string
    {
        $lowest = null;

        foreach ($component as $position) {
            if ($lowest === null || ($rows[$position]['id'] ?? 0) < ($rows[$lowest]['id'] ?? 0)) {
                $lowest = $position;
            }
        }

        return $lowest === null ? '' : $rows[$lowest]['canonical'];
    }

    /**
     * Every anchor in a contended scope except the one that keeps it.
     *
     * The survivor is the row already spelled canonically where there is one,
     * so the common case rewrites nothing. Deliberately NOT chosen by probing
     * for a canonical twin with a where clause: under the collation being
     * replaced that probe is answered by the very row being examined, and the
     * scope loses its only anchor.
     *
     * @param  array{type: string, value: string, keyed: bool, scope: string|null, policy: string}  $spec
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @param  list<int>  $component
     * @return list<array<string, string>>
     */
    private function dropAnchors(array $spec, array $rows, array $component): array
    {
        $survivor = $component[0];

        foreach ($component as $position) {
            if ($rows[$position]['value'] === $rows[$position]['canonical']) {
                $survivor = $position;

                break;
            }
        }

        $surplus = [];

        foreach ($component as $position) {
            if ($position === $survivor) {
                continue;
            }

            $row = [
                $spec['type'] => $rows[$position]['type'],
                $spec['value'] => $rows[$position]['value'],
            ];

            if ($spec['scope'] !== null) {
                $row[$spec['scope']] = $rows[$position]['scope'];
            }

            $surplus[] = $row;
        }

        return $surplus;
    }

    /**
     * @param  array{type: string, value: string, keyed: bool, scope: string|null, policy: string}  $spec
     * @param  list<int>  $doomed
     * @param  list<array<string, string>>  $surplus
     */
    private function discard(string $table, array $spec, array $doomed, array $surplus): void
    {
        if ($doomed !== []) {
            $this->connection->table($table)->whereIn('id', $doomed)->delete();
        }

        if ($surplus === []) {
            return;
        }

        // One statement, however many anchors: a delete per row would scale
        // with the damage rather than with the tables.
        $this->connection->table($table)->where(static function (Builder $outer) use ($surplus): void {
            foreach ($surplus as $row) {
                $outer->orWhere(static function (Builder $inner) use ($row): void {
                    foreach ($row as $column => $value) {
                        $inner->where($column, $value);
                    }
                });
            }
        })->delete();
    }

    /**
     * Rewrite every surviving row that is not spelled canonically.
     *
     * Keyed on the STORED SPELLING rather than on a row id, which is what keeps
     * this to a statement per chunk instead of one per row: the canonical form
     * is a function of the spelling, so one CASE arm serves every row that
     * shares a spelling. The canonical values come from PHP -- no SQL function
     * normalizes Unicode, and lower() alone leaves a decomposed address in a
     * spelling the application can no longer match.
     *
     * @param  array{type: string, value: string, keyed: bool, scope: string|null, policy: string}  $spec
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @param  list<int>  $doomed
     * @param  list<array<string, string>>  $surplus
     */
    private function rewrite(string $table, array $spec, array $rows, array $doomed, array $surplus): void
    {
        /** @var list<array{string, string}> $types */
        $types = [];
        /** @var list<array{string, string}> $values */
        $values = [];
        $seenType = [];
        $seenValue = [];
        $deleted = array_fill_keys($doomed, true);

        foreach ($rows as $row) {
            if ($row['id'] !== null && isset($deleted[$row['id']])) {
                continue;
            }

            if ($row['id'] === null && $this->isSurplus($spec, $row, $surplus)) {
                continue;
            }

            if ($row['type'] !== $row['canonicalType'] && ! isset($seenType[$row['type']])) {
                $seenType[$row['type']] = true;
                $types[] = [$row['type'], $row['canonicalType']];
            }

            if ($row['value'] !== $row['canonical'] && ! isset($seenValue[$row['value']])) {
                $seenValue[$row['value']] = true;
                $values[] = [$row['value'], $row['canonical']];
            }
        }

        $this->rewriteColumn($table, $spec['type'], $types);
        $this->rewriteColumn($table, $spec['value'], $values);
    }

    /**
     * @param  array{type: string, value: string, keyed: bool, scope: string|null, policy: string}  $spec
     * @param  array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}  $row
     * @param  list<array<string, string>>  $surplus
     */
    private function isSurplus(array $spec, array $row, array $surplus): bool
    {
        foreach ($surplus as $dropped) {
            if (($dropped[$spec['type']] ?? null) === $row['type']
                && ($dropped[$spec['value']] ?? null) === $row['value']
                && ($spec['scope'] === null || ($dropped[$spec['scope']] ?? null) === $row['scope'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * @param  list<array{string, string}>  $pairs
     */
    private function rewriteColumn(string $table, string $column, array $pairs): void
    {
        if ($pairs === []) {
            return;
        }

        $quoted = $this->quote($column);

        foreach (array_chunk($pairs, self::CHUNK) as $chunk) {
            $arms = '';
            $bindings = [];
            $stored = [];

            foreach ($chunk as [$from, $to]) {
                $arms .= ' when ? then ?';
                $bindings[] = $from;
                $bindings[] = $to;
                $stored[] = $from;
            }

            $this->connection->update(sprintf(
                'update %s set %s = case %s%s else %s end where %s in (%s)',
                $this->quote($table),
                $quoted,
                $quoted,
                $arms,
                $quoted,
                $quoted,
                implode(', ', array_fill(0, count($stored), '?')),
            ), array_merge($bindings, $stored));
        }
    }

    /**
     * Install the deterministic collation.
     *
     * One statement per table rather than per column: eight ALTERs otherwise run
     * on every test-suite migration as well as on every real upgrade.
     */
    private function convert(): void
    {
        $driver = $this->connection->getDriverName();

        /*
         * SQLite's default BINARY collation already compares text as bytes, so
         * there is nothing to install there and nothing that could disagree.
         */
        if ($driver === 'sqlite') {
            return;
        }

        foreach (self::TABLES as $table => $spec) {
            $clauses = [];

            foreach (['type', 'value'] as $role) {
                $column = $this->quote($spec[$role]);
                $length = self::LENGTHS[$role];

                $clauses[] = $driver === 'mysql'
                    ? sprintf(
                        'modify %s varchar(%d) character set utf8mb4 collate utf8mb4_bin not null',
                        $column,
                        $length,
                    )
                    : sprintf('alter column %s type varchar(%d) collate "C"', $column, $length);
            }

            $this->connection->statement(sprintf('alter table %s %s', $this->quote($table), implode(', ', $clauses)));
        }
    }

    private function quote(string $identifier): string
    {
        return $this->connection->getDriverName() === 'mysql'
            ? '`' . $identifier . '`'
            : '"' . $identifier . '"';
    }

    private function text(stdClass $row, string $column): string
    {
        $value = $row->{$column} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    private function number(stdClass $row, string $column): int
    {
        $value = $row->{$column} ?? null;

        return is_numeric($value) ? (int) $value : 0;
    }

    private function present(stdClass $row, string $column): bool
    {
        return ($row->{$column} ?? null) !== null;
    }
}
