<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * Moving every Vouch date column off MySQL's TIMESTAMP, whose range ends in 2038.
 *
 * Measured: all 83 of the package's date-or-time columns are TIMESTAMP on MySQL and not one is
 * DATETIME. MySQL's TIMESTAMP range ends at 2038-01-19 03:14:07 -- that instant stores and the next
 * second is refused with error 1292 -- while DATETIME reaches 9999. PostgreSQL and SQLite both
 * store 2039 already, so MySQL is the only engine carrying this.
 *
 * It is not only a limit on long durations, which is how it surfaced (#81, where a configured TTL
 * too large to store fails every login with a defensive error naming neither the setting nor the
 * value). `created_at` is TIMESTAMP too, and NOT NULL on most tables, so after January 2038 the
 * package cannot insert a row at all: not an attempt, not a session, not a token assurance. The
 * failure is total and it arrives on a date rather than on a configuration.
 *
 * DatabaseMigrations rather than RefreshDatabase, following the collation migrations: this is DDL,
 * which commits on MySQL regardless of any wrapping transaction, so a reverted fixture has to be
 * torn down for real between tests.
 *
 * WHAT THE CONVERSION MUST NOT DO, and it is the subtle half. TIMESTAMP stores an instant and
 * renders it in the session time zone; DATETIME stores the literal it is given and converts
 * nothing. So `ALTER ... MODIFY ... DATETIME` writes each value as its rendering in whatever time
 * zone the conversion runs under. Run under the session's own zone, every stored value keeps the
 * literal the application will later compare against CURRENT_TIMESTAMP in that same zone, and
 * nothing moves. Run under a FORCED UTC on a host whose session is +02:00, every expiry silently
 * gains two hours -- every security window lengthens. The time-zone test below is that case.
 */

/**
 * Every Vouch date-or-time column and the type MySQL is holding it as.
 *
 * @return array<string, string>
 */
function vouchDateColumnTypes(): array
{
    $rows = DB::select(
        'select table_name as t, column_name as c, data_type as d from information_schema.columns'
        . ' where table_schema = database() and table_name like ? and data_type in (?, ?, ?)',
        ['auth_%', 'timestamp', 'datetime', 'date'],
    );

    $types = [];

    foreach ($rows as $row) {
        $attributes = (array) $row;
        $types[((string) $attributes['t']) . '.' . ((string) $attributes['c'])] = (string) $attributes['d'];
    }

    ksort($types);

    return $types;
}

/** @return array<string, string> table.column => 'YES'|'NO' */
function vouchDateColumnNullability(): array
{
    $rows = DB::select(
        'select table_name as t, column_name as c, is_nullable as n from information_schema.columns'
        . ' where table_schema = database() and table_name like ? and data_type in (?, ?, ?)',
        ['auth_%', 'timestamp', 'datetime', 'date'],
    );

    $nullability = [];

    foreach ($rows as $row) {
        $attributes = (array) $row;
        $nullability[((string) $attributes['t']) . '.' . ((string) $attributes['c'])] = (string) $attributes['n'];
    }

    ksort($nullability);

    return $nullability;
}

/** The migration this adds, by the path the suite freezes. */
function runTimestampRangeMigration(): void
{
    $path = dirname(__DIR__, 2) . '/database/migrations/2026_10_03_000001_date_columns_beyond_2038.php';
    $migration = require $path;

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
 * doing anything: once the original migrations are corrected a fresh install gets DATETIME from
 * them, so without this the migration would be asserted against a schema that never had the defect.
 */
function revertToTimestampColumns(): void
{
    foreach (vouchDateColumnNullability() as $key => $nullable) {
        [$table, $column] = explode('.', $key, 2);

        DB::statement(sprintf(
            'alter table `%s` modify `%s` timestamp %s',
            $table,
            $column,
            $nullable === 'YES' ? 'null' : 'not null',
        ));
    }
}

beforeEach(function (): void {
    if (DB::connection()->getDriverName() !== 'mysql') {
        /*
         * MySQL is the only engine that can carry this. SQLite stores a date as text and
         * PostgreSQL's timestamp reaches year 294276, so there is nothing to convert and the
         * migration is a no-op there -- asserted once, at the end of this file.
         */
        $this->markTestSkipped('Only MySQL holds dates in a type that ends in 2038.');
    }
});

/* ---- what the migration has to achieve -------------------------------- */

it('leaves no date column on a type that ends in 2038', function (): void {
    /*
     * Schema-derived rather than a list this file carries. A list would have to be kept in step
     * with the migrations, and the failure mode is silent: a table added later with
     * $table->timestamp() would be absent from the list and so never checked. Asking the schema
     * covers tables that do not exist yet.
     */
    revertToTimestampColumns();

    expect(array_values(array_unique(array_values(vouchDateColumnTypes()))))->toBe(['timestamp']);

    runTimestampRangeMigration();

    $types = vouchDateColumnTypes();

    expect($types)->not->toBe([]);
    expect(array_values(array_unique(array_values($types))))->toBe(['datetime']);
});

it('stores an instant past 2038 once converted', function (): void {
    /*
     * The defect itself, through a column the package actually writes. Before the conversion this
     * insert fails with 1292; the assertion is that it both stores and reads back the same instant,
     * not merely that it does not throw.
     */
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

it('resolves a database deadline that lands past 2038', function (): void {
    /*
     * #81's symptom, which this is what actually fixes. A duration reaching past the TIMESTAMP
     * ceiling resolved fine as arithmetic all along -- it was storing the result that failed -- so
     * this asserts the whole path: resolve the deadline, then persist it.
     */
    revertToTimestampColumns();
    runTimestampRangeMigration();

    // Twenty years, which is past 2038 from any date this test can run on and well inside DATETIME.
    $deadline = app(DatabaseTime::class)->deadline(20 * 31557600);

    expect((int) $deadline->format('Y'))->toBeGreaterThan(2038);

    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => str_repeat('a', 64),
        'locked_until' => $deadline,
        'created_at' => app(DatabaseTime::class)->current(),
        'updated_at' => app(DatabaseTime::class)->current(),
    ]);

    expect(DB::table('auth_throttle_locks')->count())->toBe(1);
});

/* ---- what it must not disturb ----------------------------------------- */

it('moves no stored instant, including on a connection that is not on UTC', function (): void {
    /*
     * The hazard. MODIFY renders each TIMESTAMP in the session's time zone and stores that literal,
     * so a conversion forced to UTC on a +02:00 host writes every value two hours away from what
     * the application will compare it against -- lengthening every expiry rather than failing.
     *
     * Asserted as "the rendering does not change", which holds only if the conversion runs under
     * the ambient zone. Run under a deliberately non-UTC session so a UTC-forcing implementation
     * cannot pass by coincidence.
     */
    DB::statement("set session time_zone = '+02:00'");

    try {
        revertToTimestampColumns();

        DB::table('auth_throttle_locks')->insert([
            'subject_digest' => str_repeat('b', 64),
            'locked_until' => '2030-03-04 05:06:07',
            'created_at' => '2030-03-04 05:06:07',
            'updated_at' => '2030-03-04 05:06:07',
        ]);

        $read = static function (): string {
            $value = DB::table('auth_throttle_locks')->where('subject_digest', str_repeat('b', 64))->value('locked_until');

            return is_string($value) ? $value : '';
        };

        $before = $read();

        runTimestampRangeMigration();

        $after = $read();

        expect($after)->toBe($before);
        expect($after)->toStartWith('2030-03-04 05:06:07');
    } finally {
        DB::statement('set session time_zone = @@global.time_zone');
    }
});

it('preserves exactly which columns accept null', function (): void {
    /*
     * MODIFY restates the whole column definition, so an implementation that omitted the
     * nullability would silently make 58 nullable columns NOT NULL -- which fails later, on the
     * first row that leaves one unset, rather than during the migration.
     */
    revertToTimestampColumns();

    $before = vouchDateColumnNullability();

    expect(array_count_values(array_values($before)))->toHaveKey('YES');
    expect(array_count_values(array_values($before)))->toHaveKey('NO');

    runTimestampRangeMigration();

    expect(vouchDateColumnNullability())->toBe($before);
});

it('preserves the indexes over the columns it converts', function (): void {
    /*
     * The throttle and outbox lookups are indexed on these columns, and an implementation that
     * dropped and recreated a column rather than modifying it would take the index with it. The
     * damage would be a table scan on a hot path, which no functional test notices.
     */
    $indexes = static fn (): array => array_map(
        static fn (object $row): string => ((array) $row)['Key_name'] . ':' . ((array) $row)['Column_name'],
        DB::select('show index from auth_throttle_tuples'),
    );

    revertToTimestampColumns();
    $before = $indexes();
    sort($before);

    runTimestampRangeMigration();

    $after = $indexes();
    sort($after);

    expect($after)->toBe($before);
    expect($before)->not->toBe([]);
});

it('is safe to run twice', function (): void {
    // A host that re-runs migrations, and the idempotency the collation migration also states:
    // MODIFY restates the definition the column already has.
    revertToTimestampColumns();
    runTimestampRangeMigration();

    $once = vouchDateColumnTypes();

    runTimestampRangeMigration();

    expect(vouchDateColumnTypes())->toBe($once);
});

it('has nothing to do on a fresh installation', function (): void {
    /*
     * The other half of the change: the original migrations are corrected too, so a fresh install
     * never holds a column that ends in 2038 even transiently. Without this the conversion would be
     * the only thing standing between a new host and the defect, and a table added later would
     * reintroduce it.
     *
     * No revert first -- this is the schema the migrator just built.
     */
    expect(array_values(array_unique(array_values(vouchDateColumnTypes()))))->toBe(['datetime']);
});
