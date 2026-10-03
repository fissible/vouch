<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(DatabaseMigrations::class);

/*
 * Moving every Vouch date column off MySQL's TIMESTAMP, whose range ends in 2038.
 *
 * Measured: all 83 of the package's date-or-time columns are TIMESTAMP on MySQL and not one is
 * DATETIME. MySQL's TIMESTAMP range ends at 2038-01-19 03:14:07 -- that instant stores and the next
 * second is refused with error 1292 -- while DATETIME reaches 9999. PostgreSQL and SQLite both
 * store 2039 already, so MySQL alone carries this.
 *
 * It is not only a limit on long durations, which is how it surfaced in #81. created_at is
 * TIMESTAMP too, so after January 2038 the package cannot insert a row at all: not an attempt, not
 * a session, not a token assurance. The failure is total and it arrives on a date rather than on a
 * configuration.
 *
 * THE CONTRACT: UTC, OR REFUSE.
 *
 * TIMESTAMP stores an instant and renders it in the session time zone; DATETIME stores the literal
 * it is given and converts nothing. So MODIFY writes each value as its rendering in whatever zone
 * the conversion runs under, and the zone is part of the decision rather than an implementation
 * detail. Both available conventions were measured:
 *
 *   Under the session's OWN zone, every rendering is preserved -- and information can be destroyed.
 *   The UTC instants 2030-10-27 00:30 and 01:30, epochs 1919291400 and 1919295000, both render in
 *   Europe/Berlin as 02:30, so an ambient conversion leaves ONE distinct value where there were
 *   two. Over a column with a unique index the ALTER fails outright with 1062 instead.
 *
 *   Under UTC, every epoch is preserved exactly, and the rendering changes for a host that is not
 *   already on UTC: 05:06:07 on a +02:00 connection becomes 03:06:07, so windows would be read two
 *   hours EARLIER unless the runtime connection moves to UTC with the data.
 *
 * The package takes the second and will not paper over the difference: the migration converts only
 * on a UTC connection, and REFUSES otherwise, naming what to set. A host on a named or offset zone
 * is told to coordinate rather than silently losing an hour of every expiry, and a host already on
 * UTC -- which is what the shipped container and most deployments use -- sees no difference.
 *
 * DatabaseMigrations rather than RefreshDatabase, following the collation migrations: this is DDL,
 * which commits on MySQL regardless of any wrapping transaction, so a reverted fixture has to be
 * torn down for real between tests.
 */

/** Vouch's own tables, with the underscore ESCAPED: `auth_%` unescaped also matches a host's
 * `authentication_events`, because `_` is a single-character wildcard in LIKE. */
const VOUCH_TABLE_PATTERN = 'auth\_%';

/**
 * Every Vouch date-or-time column, with the type and nullability MySQL is holding it as.
 *
 * Asked of the schema rather than listed here. A list would need keeping in step with the
 * migrations and fails silently: a table added later with $table->timestamp() would be absent from
 * it and so never checked.
 *
 * @return array<string, string> table.column => 'type|nullable'
 */
function vouchDateColumns(): array
{
    $rows = DB::select(
        'select table_name as t, column_name as c, data_type as d, is_nullable as n'
        . ' from information_schema.columns'
        . ' where table_schema = database() and table_name like ? and data_type in (?, ?, ?)',
        [VOUCH_TABLE_PATTERN, 'timestamp', 'datetime', 'date'],
    );

    $columns = [];

    foreach ($rows as $row) {
        $attributes = (array) $row;
        $columns[((string) $attributes['t']) . '.' . ((string) $attributes['c'])]
            = ((string) $attributes['d']) . '|' . ((string) $attributes['n']);
    }

    ksort($columns);

    return $columns;
}

/** @return list<string> every index component, with uniqueness and position, over every Vouch table */
function vouchDateIndexes(): array
{
    $rows = DB::select(
        'select s.table_name as t, s.index_name as i, s.seq_in_index as p, s.column_name as c,'
        . ' s.non_unique as nu from information_schema.statistics s'
        . ' where s.table_schema = database() and s.table_name like ?',
        [VOUCH_TABLE_PATTERN],
    );

    $indexes = [];

    foreach ($rows as $row) {
        $a = (array) $row;
        // Position and uniqueness included: a unique composite index replaced by a non-unique one
        // with its columns reversed produces an identical snapshot without them.
        $indexes[] = sprintf(
            '%s.%s[%s] %s unique=%s',
            (string) $a['t'],
            (string) $a['i'],
            (string) $a['p'],
            (string) $a['c'],
            ((string) $a['nu']) === '0' ? 'yes' : 'no',
        );
    }

    sort($indexes);

    return $indexes;
}

/** The migration this adds, by the path the suite freezes. */
function runTimestampRangeMigration(): void
{
    $migration = require dirname(__DIR__, 2) . '/database/migrations/2026_10_03_000001_date_columns_beyond_2038.php';

    /*
     * Narrowed rather than annotated, as the collation migration test does: Migration declares no
     * up(), so calling it on the declared type is an error at level 9 and an inline annotation is
     * forbidden here.
     */
    if (! is_object($migration) || ! $migration instanceof Migration || ! is_callable([$migration, 'up'])) {
        throw new RuntimeException('The 2038 migration did not return a migration.');
    }

    $migration->up();
}

/**
 * Put every date column back on TIMESTAMP.
 *
 * The fixture for "a host that already installed Vouch", and the only way to observe the migration
 * doing anything: the original migrations are corrected too, so a fresh install gets DATETIME from
 * them and without this the conversion would be asserted against a schema that never had the defect.
 */
function revertToTimestampColumns(): void
{
    foreach (vouchDateColumns() as $key => $definition) {
        [$table, $column] = explode('.', $key, 2);
        [, $nullable] = explode('|', $definition, 2);

        DB::statement(sprintf(
            'alter table `%s` modify `%s` timestamp %s',
            $table,
            $column,
            $nullable === 'YES' ? 'null' : 'not null',
        ));
    }
}

/* ---- what the migration has to achieve -------------------------------- */

it('leaves no Vouch date column on a type that ends in 2038', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    revertToTimestampColumns();

    $types = array_map(static fn (string $d): string => explode('|', $d, 2)[0], vouchDateColumns());

    expect(array_values(array_unique(array_values($types))))->toBe(['timestamp']);

    runTimestampRangeMigration();

    $converted = array_map(static fn (string $d): string => explode('|', $d, 2)[0], vouchDateColumns());

    expect($converted)->not->toBe([]);
    expect(array_values(array_unique(array_values($converted))))->toBe(['datetime']);
});

it('stores an instant past 2038 once converted', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    revertToTimestampColumns();
    runTimestampRangeMigration();

    DB::table('auth_attempts')->insert([
        'handle' => 'beyond@example.test',
        'state' => 'pending',
        'version' => 1,
        'identifier' => 'beyond@example.test',
        'expires_at' => '2045-06-01 12:00:00',
        'created_at' => '2045-06-01 12:00:00',
        'updated_at' => '2045-06-01 12:00:00',
    ]);

    $stored = DB::table('auth_attempts')->where('handle', 'beyond@example.test')->value('expires_at');

    expect(is_string($stored) ? $stored : '')->toStartWith('2045-06-01 12:00:00');
});

it('resolves and then persists a deadline that lands past 2038', function (): void {
    /*
     * #81's symptom, and this is what fixes it. The duration resolved fine as arithmetic all
     * along -- it was STORING the result that failed -- so the deadline is read back rather than
     * the row merely counted.
     */
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    revertToTimestampColumns();
    runTimestampRangeMigration();

    $deadline = app(DatabaseTime::class)->deadline(20 * 31557600);

    expect((int) $deadline->format('Y'))->toBeGreaterThan(2038);

    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => str_repeat('a', 64),
        'locked_until' => $deadline,
        'created_at' => app(DatabaseTime::class)->current(),
        'updated_at' => app(DatabaseTime::class)->current(),
    ]);

    $read = DB::table('auth_throttle_locks')->where('subject_digest', str_repeat('a', 64))->value('locked_until');

    expect(is_string($read) ? substr($read, 0, 19) : '')->toBe($deadline->format('Y-m-d H:i:s'));
});

/* ---- the UTC contract ------------------------------------------------- */

it('preserves every instant exactly, by epoch, when the connection is on UTC', function (): void {
    /*
     * The B-contract assertion. Rendering is NOT the property -- under UTC it legitimately changes
     * for a host that was not on UTC -- so what is asserted is that no instant moves, across every
     * converted column rather than one of them.
     */
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }


    DB::statement("set session time_zone = '+00:00'");
    revertToTimestampColumns();

    $seed = [
        ['subject_digest' => str_repeat('c', 64), 'locked_until' => '2030-03-04 05:06:07'],
        // Either side of a northern-hemisphere daylight-saving boundary, an hour apart. These are
        // the two that collapse into one under an ambient named-zone conversion.
        ['subject_digest' => str_repeat('d', 64), 'locked_until' => '2030-10-27 00:30:00'],
        ['subject_digest' => str_repeat('e', 64), 'locked_until' => '2030-10-27 01:30:00'],
    ];

    foreach ($seed as $row) {
        DB::table('auth_throttle_locks')->insert($row + [
            'created_at' => $row['locked_until'],
            'updated_at' => $row['locked_until'],
        ]);
    }

    $epochs = static fn (): array => array_map(
        static fn (object $r): string => (string) ((array) $r)['e'],
        DB::select('select unix_timestamp(locked_until) as e from auth_throttle_locks order by subject_digest'),
    );

    $before = $epochs();

    expect($before)->toHaveCount(3);
    // The pair really is an hour apart, so the collapse this guards against is reachable.
    expect((int) $before[2] - (int) $before[1])->toBe(3600);

    runTimestampRangeMigration();

    expect($epochs())->toBe($before);
});

it('refuses to convert on a connection that is not on UTC, and changes nothing', function (string $zone): void {
    /*
     * The contract's other half, and the reason it is a refusal rather than a best effort. Measured
     * on a named zone: two instants an hour apart both render as 02:30 in Europe/Berlin, so an
     * ambient conversion leaves one distinct value where there were two -- or fails with 1062 over
     * a unique index. Converting under UTC regardless would instead read every existing window two
     * hours early on such a host.
     *
     * So neither is done silently. The operator is told, and the schema is left exactly as it was:
     * a refusal that had already converted half the tables would be worse than no refusal.
     */
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }


    DB::statement("set session time_zone = '+00:00'");
    revertToTimestampColumns();
    $before = vouchDateColumns();

    DB::statement('set session time_zone = ?', [$zone]);

    try {
        expect(fn () => runTimestampRangeMigration())
            ->toThrow(RuntimeException::class, 'UTC');

        DB::statement("set session time_zone = '+00:00'");

        expect(vouchDateColumns())->toBe($before);
    } finally {
        DB::statement("set session time_zone = '+00:00'");
    }
})->with([
    'a positive offset' => '+02:00',
    'a negative offset' => '-05:00',
    'a named zone with daylight saving' => 'Europe/Berlin',
]);

/* ---- what it must not disturb ----------------------------------------- */

it('preserves exactly which columns accept null', function (): void {
    /*
     * MODIFY restates the whole column definition, so an implementation that omitted the
     * nullability would silently make 58 nullable columns NOT NULL -- measured: a MODIFY ...
     * DATETIME with no nullability clause produces a NULLABLE column, so the damage runs the other
     * way too, and either way it surfaces later on the first row that leaves one unset.
     */
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    DB::statement("set session time_zone = '+00:00'");
    revertToTimestampColumns();

    $before = vouchDateColumns();
    $nullability = array_map(static fn (string $d): string => explode('|', $d, 2)[1], $before);

    expect(array_count_values(array_values($nullability)))->toHaveKey('YES');
    expect(array_count_values(array_values($nullability)))->toHaveKey('NO');

    runTimestampRangeMigration();

    expect(array_map(static fn (string $d): string => explode('|', $d, 2)[1], vouchDateColumns()))
        ->toBe($nullability);
});

it('preserves every index, with its uniqueness and its column order', function (): void {
    /*
     * The throttle and outbox lookups are indexed on these columns. An implementation that dropped
     * and recreated a column rather than modifying it would take the index with it, and the damage
     * would be a table scan on a hot path that no functional test notices.
     *
     * Uniqueness and position are part of the snapshot because without them a unique composite
     * index replaced by a non-unique one with reversed columns compares equal.
     */
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    DB::statement("set session time_zone = '+00:00'");
    revertToTimestampColumns();

    $before = vouchDateIndexes();

    expect($before)->not->toBe([]);

    runTimestampRangeMigration();

    expect(vouchDateIndexes())->toBe($before);
});

it('leaves a host table alone even when its name looks like one of ours', function (): void {
    /*
     * Ownership. `auth_%` is not the package's table set: `_` is a single-character wildcard, so an
     * unescaped pattern also matches a host's own authentication_events, author_events or
     * auth_company_events. A conversion driven by that pattern would rewrite tables the package
     * does not own, and this is what notices.
     */
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    DB::statement("set session time_zone = '+00:00'");

    DB::statement('create table authentication_events (id int primary key, occurred_at timestamp null)');

    try {
        revertToTimestampColumns();
        runTimestampRangeMigration();

        $type = DB::select(
            'select data_type as d from information_schema.columns where table_schema = database()'
            . ' and table_name = ? and column_name = ?',
            ['authentication_events', 'occurred_at'],
        );

        expect((string) ((array) $type[0])['d'])->toBe('timestamp');
    } finally {
        DB::statement('drop table if exists authentication_events');
    }
});

it('is safe to run twice', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    DB::statement("set session time_zone = '+00:00'");
    revertToTimestampColumns();
    runTimestampRangeMigration();

    $once = vouchDateColumns();

    runTimestampRangeMigration();

    expect(vouchDateColumns())->toBe($once);
});

/* ---- the originals, and the other engines ----------------------------- */

it('builds a fresh installation with no date column that ends in 2038', function (): void {
    /*
     * The other half of the change: the original migrations are corrected, so a new host never
     * holds a column that ends in 2038 even transiently, and a table added later does not
     * reintroduce it.
     *
     * The upgrade is EXCLUDED while the schema is rebuilt, because DatabaseMigrations runs it as
     * part of migrate:fresh -- so asserting against that schema would let an upgrade-only change
     * pass while every original migration stayed defective.
     */
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }

    DB::statement("set session time_zone = '+00:00'");

    foreach (array_keys(vouchDateColumns()) as $key) {
        Schema::dropIfExists(explode('.', $key, 2)[0]);
    }

    $files = glob(dirname(__DIR__, 2) . '/database/migrations/*.php') ?: [];
    sort($files);
    $replayed = 0;

    foreach ($files as $file) {
        if (str_contains($file, 'date_columns_beyond_2038')) {
            continue;
        }

        $migration = require $file;

        if (! is_object($migration) || ! $migration instanceof Migration || ! is_callable([$migration, 'up'])) {
            continue;
        }

        $migration->up();
        $replayed++;
    }

    // The replay has to have actually happened, or an empty schema would pass vacuously.
    expect($replayed)->toBeGreaterThan(10);

    $columns = vouchDateColumns();

    expect($columns)->not->toBe([]);
    expect(array_values(array_unique(array_map(
        static fn (string $d): string => explode('|', $d, 2)[0],
        $columns,
    ))))->toBe(['datetime']);
});

it('changes nothing on an engine whose dates already reach past 2038', function (): void {
    /*
     * SQLite stores a date as text and PostgreSQL's timestamp reaches year 294276, so there is
     * nothing to convert. Asserted as a genuine no-op -- schema and rows unchanged -- rather than
     * left to the unconditional skip, which reported zero assertions and so established nothing.
     */
    if (! skipUnlessMysql()) {
        $this->markTestSkipped('MySQL is the engine that needs the conversion.');
    }

    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => str_repeat('f', 64),
        'locked_until' => '2045-06-01 12:00:00',
        'created_at' => '2045-06-01 12:00:00',
        'updated_at' => '2045-06-01 12:00:00',
    ]);

    $columns = Schema::getColumns('auth_throttle_locks');

    runTimestampRangeMigration();

    expect(Schema::getColumns('auth_throttle_locks'))->toBe($columns);

    $stored = DB::table('auth_throttle_locks')->where('subject_digest', str_repeat('f', 64))->value('locked_until');

    expect(is_string($stored) ? substr($stored, 0, 19) : '')->toBe('2045-06-01 12:00:00');
});
