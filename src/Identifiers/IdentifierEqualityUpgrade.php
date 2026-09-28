<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\Connection;
use InvalidArgumentException;
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
 * A refusal changes NOTHING -- not a row, not a column -- so an operator who
 * reconciles the reported rows re-runs against the database they started with
 * rather than one that is already half converted.
 *
 * Not serializable against concurrent writers, and deliberately so. Deciding
 * everything before writing anything is what makes a refusal leave no trace;
 * the cost is that a row inserted between the scan and the rewrite keeps its
 * non-canonical spelling and is invisible to the collision check. Locking three
 * tables for the length of a full scan is a worse operational story than
 * pausing traffic, which is what docs/operations.md asks for.
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
     * `refuse` is an account row, `transient` a short-lived credential.
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
    ];

    /** Characters each identifier column holds, as the tables declare them. */
    private const LENGTHS = ['type' => 32, 'value' => 255];

    /**
     * The collation MySQL gets, named here because two migrations install it.
     *
     * NO PAD, which is the entire point of the name. `utf8mb4_bin` is
     * deterministic and PAD SPACE both, so it equated a trailing ASCII space
     * where PostgreSQL's C and SQLite's BINARY do not -- the engine-dependent
     * equality this conversion exists to remove, surviving inside it. Measured:
     * of MySQL's binary collations only utf8mb4_0900_bin is NO PAD; the other
     * forty pad. Deterministic and NO PAD are different properties and a name
     * ending in `_bin` carries only the first.
     *
     * It exists from MySQL 8.0 only, which is what makes 8.0 this package's
     * floor. docs/operations.md states that as a requirement.
     */
    public const MYSQL_COLLATION = 'utf8mb4_0900_bin';

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

        foreach (self::TABLES as $table => $spec) {
            $triage = $this->triage($table, $spec, $scanned[$table]);

            $refusals = array_merge($refusals, $triage['refusals']);
            $doomed[$table] = $triage['doomed'];
        }

        if ($refusals !== []) {
            throw new IdentifierCollisionsFound($refusals);
        }

        /*
         * Schema first, then rows. Every update below names an exact spelling,
         * and only a deterministic collation makes "this spelling" mean one row:
         * under the collation being replaced, a statement aimed at one spelling
         * also reaches every other the engine considers equal to it.
         */
        self::installCollation($this->connection);

        foreach (self::TABLES as $table => $spec) {
            $this->discard($table, $doomed[$table]);
            $this->rewrite($table, $spec, $scanned[$table], $doomed[$table]);
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
     * What this table's collisions cost: rows to refuse over, rows to delete.
     *
     * @param  array{type: string, value: string, keyed: bool, scope: string|null, policy: string}  $spec
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @return array{refusals: list<IdentifierCollision>, doomed: list<int>}
     */
    private function triage(string $table, array $spec, array $rows): array
    {
        /** @var list<IdentifierCollision> $refusals */
        $refusals = [];
        /** @var list<int> $doomed */
        $doomed = [];

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
                $this->canonicalValues($rows, $component),
            );
        }

        return ['refusals' => $refusals, 'doomed' => $doomed];
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
     * Every canonical value the group lands on, ascending.
     *
     * One for a merge. SEVERAL for a split, which is the case the single
     * reported value cannot express: naming only one would tell an operator
     * that two rows want one address when the truth is the opposite -- this
     * database considers them one address and the change makes them two.
     *
     * @param  list<array{id: int|null, scope: string, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}>  $rows
     * @param  list<int>  $component
     * @return list<string>
     */
    private function canonicalValues(array $rows, array $component): array
    {
        $values = [];

        foreach ($component as $position) {
            /*
             * A list, not the keys of a set. A canonical value that is all
             * digits becomes an INT array key, which would hand a list<string>
             * back with integers in it.
             */
            if (! in_array($rows[$position]['canonical'], $values, true)) {
                $values[] = $rows[$position]['canonical'];
            }
        }

        sort($values);

        return $values;
    }

    /**
     * @param  list<int>  $doomed
     */
    private function discard(string $table, array $doomed): void
    {
        if ($doomed === []) {
            return;
        }

        $this->connection->table($table)->whereIn('id', $doomed)->delete();
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
     */
    private function rewrite(string $table, array $spec, array $rows, array $doomed): void
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
     * One statement per table rather than per column: six ALTERs otherwise run
     * on every test-suite migration as well as on every real upgrade.
     *
     * The two engines are not symmetric about what survives. MySQL's MODIFY
     * replaces the WHOLE column definition, so a DEFAULT or COMMENT a host had
     * added to one of these columns is dropped, and naming the character set
     * converts the data on a table that was not utf8mb4; PostgreSQL's ALTER
     * COLUMN ... TYPE preserves both. Latent rather than live -- none of the
     * six carries either today -- and recorded so the next reader need not
     * rediscover it.
     *
     * Static, and public, because two migrations install this collation: the
     * conversion above, so a fresh installation never transiently holds a
     * padding one, and the follow-up that moves a host which already ran the
     * conversion off the padding collation it installed. Neither needs a
     * canonicalizer to change a collation, and the alternative -- each naming
     * the collation itself -- is how the two came to disagree.
     */
    public static function installCollation(Connection $connection): void
    {
        $driver = $connection->getDriverName();

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
                $column = self::quoted($connection, $spec[$role]);
                $length = self::LENGTHS[$role];

                /*
                 * The whole definition, every time. MODIFY replaces it rather
                 * than amending it, so the width and the nullability have to be
                 * restated here or a conversion silently widens what an
                 * identifier column accepts.
                 */
                /*
                 * Named drivers, with a refusal for anything else. A ternary sent
                 * every non-MySQL driver down the PostgreSQL branch, so a host on
                 * MariaDB -- which Laravel reports as its own driver name -- was
                 * handed `alter column ... type ... collate "C"`: syntax MariaDB does
                 * not accept, naming a collation it does not have. An engine this
                 * package has never tested should be told so, not guessed at.
                 */
                $clauses[] = match ($driver) {
                    'mysql' => sprintf(
                        'modify %s varchar(%d) character set utf8mb4 collate %s not null',
                        $column,
                        $length,
                        self::MYSQL_COLLATION,
                    ),
                    'pgsql' => sprintf('alter column %s type varchar(%d) collate "C"', $column, $length),
                    default => throw new InvalidArgumentException(
                        'Vouch cannot install a deterministic identifier collation on driver "'
                        . $driver . '". Supported engines are MySQL, PostgreSQL and SQLite.',
                    ),
                };
            }

            $connection->statement(sprintf(
                'alter table %s %s',
                self::quoted($connection, $table),
                implode(', ', $clauses),
            ));
        }
    }

    private function quote(string $identifier): string
    {
        return self::quoted($this->connection, $identifier);
    }

    /** Quoting needs the driver rather than the instance: installCollation() is static. */
    private static function quoted(Connection $connection, string $identifier): string
    {
        return match ($connection->getDriverName()) {
            'mysql' => '`' . $identifier . '`',
            // SQLite and PostgreSQL both accept the SQL-standard double quote.
            'pgsql', 'sqlite' => '"' . $identifier . '"',
            default => throw new InvalidArgumentException(
                'Vouch cannot quote an identifier for driver "' . $connection->getDriverName() . '".',
            ),
        };
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
