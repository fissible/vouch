<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\Connection;
use InvalidArgumentException;
use LogicException;
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
 * the cost is that a row inserted between the scan and the rewrite is invisible
 * to the collision check, even if the rewrite sees it. Canonicalizing that row
 * can collide with a surviving row and fail the migration on the unique
 * (type, value) index. Without transactional rollback, earlier collation changes,
 * deletes, and rewrites can remain applied. Locking three tables for the length
 * of a full scan is a worse operational story than pausing traffic, which is
 * what docs/operations.md asks for.
 *
 * #61. The scan is bounded in memory rather than proportional to the table. The
 * first version read every row of all three tables into PHP before deciding
 * anything -- measured at 857 bytes of array payload and about 1.8 KB resident
 * per row, linear -- so roughly 157k auth_identifiers rows exhausted a 128 MB
 * limit and the largest installations could not complete the upgrade at all.
 * What replaces it is a per-table working table: rows go in id-ordered chunks,
 * the engine picks out the groups worth looking at, and only those rows come
 * back to PHP. The all-or-nothing contract is unchanged -- every table is
 * scanned and every verdict reached before the first write.
 *
 * This lives here rather than inside the migration for a measured reason: a
 * migration file is recompiled on every migrate, and the suite runs hundreds of
 * them. At this size that cost 32 MB of never-reclaimed compiled classes across
 * one suite run and exhausted the pinned memory limit. An autoloaded class is
 * compiled once.
 *
 * @phpstan-type IdentifierRow array{id: int, type: string, value: string, canonicalType: string, canonical: string, key: string, loose: string, terminal: bool}
 * @phpstan-type TableSpec array{type: string, value: string, policy: string}
 * @phpstan-type RewriteChunk list<array{string, string}>
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
     *
     * Every table here is keyed by `id`, which is what lets the scan below page
     * through it. A fourth entry once described the issuance lock table, which
     * had a scope and no identifier column; #46 replaced that table with a
     * bucketed one, and the `keyed` and `scope` flags that existed only to
     * describe it went with it rather than staying as configuration no entry
     * uses and no test reaches.
     */
    private const TABLES = [
        'auth_identifiers' => [
            'type' => 'type', 'value' => 'value', 'policy' => 'refuse',
        ],
        'auth_identifier_verifications' => [
            'type' => 'identifier_type', 'value' => 'identifier_value', 'policy' => 'transient',
        ],
        'auth_recovery_proofs' => [
            'type' => 'identifier_type', 'value' => 'identifier_value', 'policy' => 'transient',
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

    /**
     * Where the scan keeps its working set.
     *
     * TEMPORARY, and that is load-bearing rather than tidy. The refusal contract
     * says a refused upgrade left no trace, and a permanent scratch table is a
     * trace -- one a row-and-column assertion cannot see. A temporary table is
     * absent from information_schema.tables, from pg_tables and from
     * sqlite_master alike because it dies with the connection, so even a process
     * killed mid-scan leaves nothing behind for the next operator to explain.
     */
    private const WORKING_TABLE = 'vouch_identifier_upgrade_scan';

    /** Rows read from the source table per statement. */
    private const SCAN_CHUNK = 500;

    /**
     * Rows written into the working table per statement.
     *
     * Smaller than the read chunk because this one is bounded by PLACEHOLDERS,
     * not by rows: seven columns, so a hundred rows is seven hundred bindings
     * and still clear of the 999 that older SQLite builds cap a statement at.
     */
    private const STORE_CHUNK = 100;

    /** Group keys named per read-back statement, on the same placeholder budget. */
    private const KEY_CHUNK = 200;

    public function apply(): void
    {
        /*
         * #90. MySQL's plain DROP TABLE commits the caller's transaction even
         * for a temporary table, leaving Laravel's depth counter unchanged.
         * DROP TEMPORARY TABLE alone would protect the scan but not the later
         * ALTER TABLE, so refuse before either can run. PostgreSQL's migrator
         * wraps this migration in a transaction; its DDL does not commit it.
         */
        if ($this->connection->getDriverName() === 'mysql' && $this->connection->transactionLevel() > 0) {
            throw new LogicException(
                'Vouch cannot run the identifier equality upgrade inside an active MySQL transaction. '
                . 'Run the upgrade outside a transaction: MySQL implicitly commits its DDL, '
                . 'so the upgrade cannot be transactional.',
            );
        }

        /*
         * Read every table BEFORE deciding anything, and decide everything
         * before writing anything. The refusal contract is that a refused
         * upgrade left no trace, which a table-at-a-time convert-then-check
         * cannot honour.
         */
        /** @var list<IdentifierCollision> $refusals */
        $refusals = [];
        /** @var array<string, list<int>> $doomed */
        $doomed = [];

        foreach (self::TABLES as $table => $spec) {
            $scanned = $this->scan($table, $spec);

            $refusals = array_merge($refusals, $scanned['refusals']);
            $doomed[$table] = $scanned['doomed'];
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

            $this->rewrite($table, $spec);
        }
    }

    /**
     * Everything one identifier table costs, decided without holding it in PHP.
     *
     * Three steps, and the split between them is what bounds the memory. The
     * fill streams the table through a working table in id-ordered chunks,
     * computing canonical forms in PHP as it goes. The engine then names the
     * groups worth a second look. Only those rows come back, and the existing
     * component walk and triage run over that small set.
     *
     * @param  TableSpec  $spec
     * @return array{refusals: list<IdentifierCollision>, doomed: list<int>}
     */
    private function scan(string $table, array $spec): array
    {
        $this->createWorkingTable();

        try {
            $this->fill($table, $spec);

            return $this->triage($table, $spec, $this->candidates());
        } finally {
            /*
             * In a finally, so a refusal raised by a LATER table -- or a query
             * that fails outright -- still leaves nothing behind.
             */
            $this->connection->statement(sprintf(
                'drop table if exists %s',
                $this->quote(self::WORKING_TABLE),
            ));
        }
    }

    /**
     * The working table, with the collation the comparisons below depend on.
     *
     * Its OWN collation, and getting this wrong is the quietest way to break the
     * whole migration. Left to the MySQL server default these columns are accent-
     * and case-insensitive, so `count(distinct row_value)` folds Ada@ and ada@
     * into one, every group looks uninteresting, and the scan reports NO
     * collisions -- the defect this migration exists to prevent, reintroduced
     * inside its own machinery, on one engine only and without an error.
     * Measured. SQLite's BINARY default is already right and needs nothing.
     */
    private function createWorkingTable(): void
    {
        $driver = $this->connection->getDriverName();

        $text = match ($driver) {
            'mysql' => ' character set utf8mb4 collate ' . self::MYSQL_COLLATION,
            'pgsql' => ' collate "C"',
            'sqlite' => '',
            default => throw new InvalidArgumentException(
                'Vouch cannot build an identifier scan working table on driver "'
                . $driver . '". Supported engines are MySQL, PostgreSQL and SQLite.',
            ),
        };

        /*
         * The canonical columns are twice the width of the ones they mirror.
         * Case folding is not length-preserving -- U+0130 lowercases to two code
         * points -- so a value sitting at its column's limit can canonicalize
         * past it, and MySQL in strict mode would reject the INSERT rather than
         * the row. The headroom costs nothing; a truncated canonical form would
         * silently mis-group.
         */
        $this->connection->statement(sprintf(
            'create temporary table %s ('
            . 'row_id bigint not null, '
            . 'row_type varchar(%d)%s not null, '
            . 'row_value varchar(%d)%s not null, '
            . 'canonical_type varchar(%d)%s not null, '
            . 'canonical_value varchar(%d)%s not null, '
            . 'loose_class bigint not null, '
            . 'terminal integer not null)',
            $this->quote(self::WORKING_TABLE),
            self::LENGTHS['type'],
            $text,
            self::LENGTHS['value'],
            $text,
            self::LENGTHS['type'] * 2,
            $text,
            self::LENGTHS['value'] * 2,
            $text,
        ));
    }

    /**
     * Stream one identifier table into the working table, id-ordered.
     *
     * Each row arrives with its canonical form and the equality class the
     * column's CURRENT collation puts it in.
     *
     * The loose class is the only way a SPLIT is visible. Two rows an
     * accent-insensitive collation considers one address canonicalize apart, and
     * no amount of PHP can discover that equality -- only the engine knows it.
     * So the engine is asked, in the same statement that reads the rows, via an
     * index-backed correlated subquery rather than a query per pair.
     *
     * @param  TableSpec  $spec
     */
    private function fill(string $table, array $spec): void
    {
        $quoted = $this->quote($table);
        $type = $this->quote($spec['type']);
        $value = $this->quote($spec['value']);

        $select = [
            't.id as row_id',
            sprintf('t.%s as row_type', $type),
            sprintf('t.%s as row_value', $value),
            sprintf(
                '(select min(o.id) from %s o where o.%s = t.%s and o.%s = t.%s) as loose_class',
                $quoted,
                $type,
                $type,
                $value,
                $value,
            ),
        ];

        if ($spec['policy'] === 'transient') {
            $select[] = 't.consumed_at as consumed_at';
            $select[] = 't.burned_at as burned_at';
        }

        /*
         * Paged by the primary key rather than by OFFSET. An offset re-walks
         * everything it skips, so the scan would cost O(n squared) row reads on
         * exactly the installations this change is for.
         *
         * #89. The first page has no lower bound: explicit zero and negative
         * keys survive on SQLite and PostgreSQL. Starting at -1 only fixes
         * zero. NULL marks an unstarted scan, independently of number()'s zero
         * fallback; a real zero key is a cursor, never a reason to skip a row.
         */
        $query = sprintf(
            'select %s from %s t',
            implode(', ', $select),
            $quoted,
        );

        $cursor = null;

        do {
            /*
             * Read the source on the writer too: this scan drives DELETEs on
             * the writer, so its decisions must use the writer's rows. A replica
             * could show different rows, including omitting a terminal member.
             */
            $read = $this->connection->select(
                $query . ($cursor === null ? '' : ' where t.id > ?')
                . sprintf(' order by t.id limit %d', self::SCAN_CHUNK),
                $cursor === null ? [] : [$cursor],
                useReadPdo: false,
            );
            /** @var list<array{int, string, string, string, string, int, int}> $pending */
            $pending = [];

            foreach ($read as $row) {
                if (! $row instanceof stdClass) {
                    continue;
                }

                $id = $this->number($row, 'row_id');
                $storedType = $this->text($row, 'row_type');
                $storedValue = $this->text($row, 'row_value');
                $canonicalType = $this->canonicalizer->canonicalize($storedType);
                $canonicalValue = $this->canonicalizer->canonicalize($storedValue);

                $cursor = $id;

                $pending[] = [
                    $id,
                    $storedType,
                    $storedValue,
                    $canonicalType,
                    $canonicalValue,
                    $this->number($row, 'loose_class'),
                    $this->present($row, 'consumed_at') || $this->present($row, 'burned_at') ? 1 : 0,
                ];
            }

            $this->store($pending);
        } while (count($read) >= self::SCAN_CHUNK);
    }

    /**
     * @param  list<array{int, string, string, string, string, int, int}>  $rows
     */
    private function store(array $rows): void
    {
        foreach (array_chunk($rows, self::STORE_CHUNK) as $chunk) {
            $tuples = [];
            $bindings = [];

            foreach ($chunk as $row) {
                $tuples[] = '(?, ?, ?, ?, ?, ?, ?)';

                foreach ($row as $field) {
                    $bindings[] = $field;
                }
            }

            $this->connection->insert(sprintf(
                'insert into %s (row_id, row_type, row_value, canonical_type, canonical_value,'
                . ' loose_class, terminal) values %s',
                $this->quote(self::WORKING_TABLE),
                implode(', ', $tuples),
            ), $bindings);
        }
    }

    /**
     * Every row of every group that could possibly be a collision.
     *
     * A group is a set of rows with more than one SPELLING in it, reached
     * through either relation: rows sharing a canonical form, and rows the
     * current collation already equates. Asking the engine for the groups whose
     * spellings disagree returns every row of every such component, not merely
     * the rows the disagreement was noticed on.
     *
     * That is a claim worth stating. Identical bytes canonicalize identically
     * AND compare equal under any collation, so a row whose canonical group and
     * whose loose class are each of one spelling has a component of exactly one
     * spelling -- its neighbours' neighbours are its own. Contrapositively,
     * every row of a component with two spellings has a canonical group or a
     * loose class that disagrees with itself, so nothing is left behind and the
     * report names the whole group rather than the pair that gave it away.
     *
     * @return list<IdentifierRow>
     */
    private function candidates(): array
    {
        $working = $this->quote(self::WORKING_TABLE);
        $disagrees = ' having count(distinct row_type) > 1 or count(distinct row_value) > 1';

        /*
         * Grouped by the two canonical COLUMNS, never by a composite key built
         * in SQL. Joining them around a "\0" separator -- which is what the key
         * looks like in PHP -- truncates at the separator on PostgreSQL, where
         * text cannot hold a NUL: every row sharing a type collapses into one
         * group and unrelated addresses are reported as colliding. Silent, and
         * on that engine only.
         *
         * #91. All three reads use the writer: the temporary table belongs to
         * the session that created it. Routing only the grouped reads there
         * still fails when a collision reaches the candidate read-back below.
         */
        $merges = $this->connection->select(sprintf(
            'select canonical_type, canonical_value from %s group by canonical_type, canonical_value%s',
            $working,
            $disagrees,
        ), useReadPdo: false);

        $splits = $this->connection->select(sprintf(
            'select loose_class from %s group by loose_class%s',
            $working,
            $disagrees,
        ), useReadPdo: false);

        /**
         * Two statements and a read-back rather than one query with subqueries,
         * because MySQL refuses to open a TEMPORARY table twice in the same
         * statement -- "Can't reopen table" -- so the obvious
         * `where ... in (select ... from working group by ...)` form does not run
         * there at all.
         *
         * @var list<array{string, list<int|string>}> $conditions
         */
        $conditions = [];

        foreach ($merges as $row) {
            if (! $row instanceof stdClass) {
                continue;
            }

            $conditions[] = [
                '(canonical_type = ? and canonical_value = ?)',
                [$this->text($row, 'canonical_type'), $this->text($row, 'canonical_value')],
            ];
        }

        foreach ($splits as $row) {
            if (! $row instanceof stdClass) {
                continue;
            }

            $conditions[] = ['loose_class = ?', [$this->number($row, 'loose_class')]];
        }

        /** @var list<IdentifierRow> $rows */
        $rows = [];
        $seen = [];

        foreach (array_chunk($conditions, self::KEY_CHUNK) as $chunk) {
            $clauses = [];
            $bindings = [];

            foreach ($chunk as [$clause, $values]) {
                $clauses[] = $clause;

                foreach ($values as $binding) {
                    $bindings[] = $binding;
                }
            }

            $selected = $this->connection->select(sprintf(
                'select row_id, row_type, row_value, canonical_type, canonical_value, loose_class,'
                . ' terminal from %s where %s order by row_id',
                $working,
                implode(' or ', $clauses),
            ), $bindings, useReadPdo: false);

            foreach ($selected as $row) {
                if (! $row instanceof stdClass) {
                    continue;
                }

                $id = $this->number($row, 'row_id');

                /*
                 * A row reached through both relations arrives once per chunk it
                 * matches in, and the refusal report names ids rather than
                 * counting them -- so an operator would be handed the same row
                 * twice.
                 */
                if (isset($seen[$id])) {
                    continue;
                }

                $seen[$id] = true;
                $canonicalType = $this->text($row, 'canonical_type');
                $canonical = $this->text($row, 'canonical_value');

                $rows[] = [
                    'id' => $id,
                    'type' => $this->text($row, 'row_type'),
                    'value' => $this->text($row, 'row_value'),
                    'canonicalType' => $canonicalType,
                    'canonical' => $canonical,
                    // The NUL lives in PHP only; see the grouping note above.
                    'key' => $canonicalType . "\0" . $canonical,
                    'loose' => (string) $this->number($row, 'loose_class'),
                    'terminal' => $this->flag($row, 'terminal'),
                ];
            }
        }

        return $rows;
    }

    /**
     * What this table's collisions cost: rows to refuse over, rows to delete.
     *
     * @param  TableSpec  $spec
     * @param  list<IdentifierRow>  $rows
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
     * @param  list<IdentifierRow>  $rows
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
     * @param  list<IdentifierRow>  $rows
     * @param  list<int>  $component
     * @return list<int>
     */
    private function ids(array $rows, array $component): array
    {
        $ids = [];

        foreach ($component as $position) {
            $ids[] = $rows[$position]['id'];
        }

        sort($ids);

        return $ids;
    }

    /**
     * The canonical value a colliding group contends for, taken from its
     * lowest-numbered row so the report is stable between runs.
     *
     * @param  list<IdentifierRow>  $rows
     * @param  list<int>  $component
     */
    private function contested(array $rows, array $component): string
    {
        $lowest = null;

        foreach ($component as $position) {
            if ($lowest === null || $rows[$position]['id'] < $rows[$lowest]['id']) {
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
     * @param  list<IdentifierRow>  $rows
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
     * Recompute rewrite pairs one source page at a time, after every verdict.
     *
     * #92. Distinct changing spellings can mean one pair per row: the previous
     * accumulator peaked at 45 MiB for 100k rows and exhausted 128M at 400k.
     * Deduplication is not a bound. scan() drops its working table in finally,
     * so those pairs cannot simply be read back when apply() reaches this point.
     *
     * A second source pass keeps that lifetime and refusal cleanup intact. Keeping
     * all three working tables would broaden their lifetime through DDL and writes;
     * spooling would add file ownership and failure handling. Here the cost is
     * another bounded read and canonicalization per page, with no new resource.
     * Both reads and pair lists are bounded, including on already-canonical tables.
     * The hash-derived uppercase fixture now peaks at 6 MiB at both 100k and
     * 400k rows under 16M; the 1200-row SQLite case uses 45 statements including
     * its four assertion queries, rather than spending one update per pair.
     *
     * Page by the unchanged primary key, not by a spelling we are rewriting, and
     * read on the writer as in fill(). NULL again includes zero and negative ids.
     * Discarding precedes this pass, so deleted credentials need no rewrite pairs.
     *
     * @param  TableSpec  $spec
     */
    private function rewrite(string $table, array $spec): void
    {
        $query = sprintf(
            'select id as row_id, %s as row_type, %s as row_value from %s',
            $this->quote($spec['type']),
            $this->quote($spec['value']),
            $this->quote($table),
        );
        $cursor = null;

        do {
            $read = $this->connection->select(
                $query . ($cursor === null ? '' : ' where id > ?')
                . sprintf(' order by id limit %d', self::SCAN_CHUNK),
                $cursor === null ? [] : [$cursor],
                useReadPdo: false,
            );
            $types = [];
            $values = [];

            foreach ($read as $row) {
                if (! $row instanceof stdClass) {
                    continue;
                }

                $cursor = $this->number($row, 'row_id');
                $storedType = $this->text($row, 'row_type');
                $storedValue = $this->text($row, 'row_value');
                $canonicalType = $this->canonicalizer->canonicalize($storedType);
                $canonicalValue = $this->canonicalizer->canonicalize($storedValue);

                if ($storedType !== $canonicalType) {
                    $types[] = [$storedType, $canonicalType];
                }

                if ($storedValue !== $canonicalValue) {
                    $values[] = [$storedValue, $canonicalValue];
                }
            }

            $this->rewriteColumn($table, $spec['type'], $types);
            $this->rewriteColumn($table, $spec['value'], $values);
        } while (count($read) >= self::SCAN_CHUNK);
    }

    /**
     * Rewrite every row spelled one way into the canonical spelling of it.
     *
     * Each list belongs to one source page. A CASE arm can reach a matching row
     * on a later page too; canonicalization is idempotent, so that row then needs
     * no pair. No global set of seen spellings needs to survive between pages.
     *
     * The canonical values come from PHP -- no SQL function normalizes Unicode,
     * and lower() alone leaves a decomposed address in a spelling the
     * application can no longer match.
     *
     * @param  RewriteChunk  $pairs
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

    /**
     * A non-null terminal timestamp records consumption or burning, even when
     * SQLite returns it as integer zero. Boolean decoding loses that record.
     * Keep this separate from flag(): widening that helper to test presence
     * would incorrectly treat the working table's zero flag as true.
     */
    private function present(stdClass $row, string $column): bool
    {
        return ($row->{$column} ?? null) !== null;
    }

    /**
     * Whether the working table's boolean column says yes.
     *
     * The working table's own flag comes back as 1 or "1" from SQLite and MySQL,
     * and PostgreSQL's drivers have been known to hand a bare boolean back.
     * Reading only `is_numeric` would silently answer "not terminal" for the
     * last of those, which under the transient policy DELETES
     * the consumed proofs this upgrade is supposed to refuse over.
     */
    private function flag(stdClass $row, string $column): bool
    {
        $value = $row->{$column} ?? null;

        if (is_bool($value)) {
            return $value;
        }

        if (is_numeric($value)) {
            return (int) $value !== 0;
        }

        // Deliberately treat an unexpected non-null engine value as terminal:
        // refusing the upgrade is safer than deleting a potentially consumed proof.
        return $value !== null;
    }
}
