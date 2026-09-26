<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * #63. Moving an installation that already ran #59 off a padding collation.
 *
 * #59 installed utf8mb4_bin, whose name satisfies every check written for it and
 * which is PAD SPACE all the same. An installation upgraded then is carrying a
 * column that equates a trailing ASCII space where PostgreSQL and SQLite do not,
 * so this needs its own migration rather than an edit to #59's -- a host that has
 * already run that one will never run it again.
 *
 * DatabaseMigrations rather than RefreshDatabase: the collation is changed with
 * DDL, which commits on MySQL regardless of any wrapping transaction, so a
 * reverted fixture has to be torn down for real between tests.
 */

/** The migration this issue adds, by the path the suite freezes. */
function runNoPadMigration(): void
{
    $migration = require dirname(__DIR__, 2)
        . '/database/migrations/2026_09_25_000002_identifier_collation_without_padding.php';

    /*
     * Narrowed rather than annotated: Migration declares no up(), so calling it
     * on the declared type is an error at level 9 and an inline annotation is
     * forbidden here.
     */
    if (! is_object($migration) || ! $migration instanceof Migration || ! is_callable([$migration, 'up'])) {
        throw new RuntimeException('The no-pad collation migration did not return a migration.');
    }

    $migration->up();
}

/**
 * Put every identifier column back on the padding collation #59 installed.
 *
 * The fixture for "an installation that already upgraded", and the only way to
 * observe the migration doing anything: a fresh install gets the right collation
 * from #59 itself once that is corrected, so without this the migration would be
 * asserted against a schema that never had the defect.
 */
function revertToPaddingCollation(): void
{
    foreach (identifierColumns() as [$table, $column]) {
        $length = str_contains($column, 'type') ? 32 : 255;

        DB::statement(sprintf(
            'alter table `%s` modify `%s` varchar(%d) character set utf8mb4 collate utf8mb4_bin not null',
            $table,
            $column,
            $length,
        ));
    }
}

/** Only MySQL has a binary collation that pads; the others cannot hold the defect. */
function skipUnlessMysql(): bool
{
    return DB::connection()->getDriverName() !== 'mysql';
}

it('reports the padding collation as padding', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL has a deterministic collation that pads.');
    }

    /*
     * The control for every assertion below. comparesWithoutPadding() returns
     * true unconditionally off MySQL, so without something proving it can return
     * FALSE the whole file would pass against a migration that did nothing.
     */
    revertToPaddingCollation();

    foreach (identifierColumns() as [$table, $column]) {
        expect(comparesWithoutPadding($table, $column))
            ->toBeFalse(sprintf('%s.%s should still be padding before the migration runs', $table, $column));
    }
});

it('moves every identifier column off the padding collation', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL has a deterministic collation that pads.');
    }

    revertToPaddingCollation();
    runNoPadMigration();

    foreach (identifierColumns() as [$table, $column]) {
        expect(comparesWithoutPadding($table, $column))
            ->toBeTrue(sprintf('%s.%s must compare without padding', $table, $column))
            ->and(carriesDeterministicCollation($table, $column))
            ->toBeTrue(sprintf('%s.%s must still compare deterministically', $table, $column));
    }
});

it('stops equating a trailing space once it has run', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL has a deterministic collation that pads.');
    }

    revertToPaddingCollation();

    DB::table('auth_identifiers')->insert([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    /*
     * The premise, asserted rather than assumed: the reverted fixture really does
     * equate the padded spelling. If this stopped being true the test below would
     * pass without the migration having done anything.
     */
    expect(DB::table('auth_identifiers')->where('value', 'ada@acme.example ')->exists())->toBeTrue();

    runNoPadMigration();

    expect(DB::table('auth_identifiers')->where('value', 'ada@acme.example ')->exists())->toBeFalse()
        ->and(DB::table('auth_identifiers')->where('value', 'ada@acme.example')->exists())->toBeTrue();
});

it('admits both spellings afterwards, where the index refused one before', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL has a deterministic collation that pads.');
    }

    revertToPaddingCollation();
    runNoPadMigration();

    /*
     * unique(type, value) rejected the padded spelling as a duplicate under PAD
     * SPACE, which is the same defect seen from the write side: the constraint
     * decided two registrations were one address on one engine only.
     */
    foreach (['ada@acme.example', 'ada@acme.example ', '', ' '] as $index => $value) {
        DB::table('auth_identifiers')->insert([
            'user_id' => $index + 1,
            'type' => 'email',
            'value' => $value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /*
     * '' and ' ' are the same pair at the boundary: a padding collation equates
     * them and the index refuses the second, which is the cheapest case that
     * distinguishes padding from byte comparison.
     */
    expect(DB::table('auth_identifiers')->count())->toBe(4);
});

it('leaves the rest of the column definition alone', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL replaces a whole column definition to change a collation.');
    }

    revertToPaddingCollation();

    $before = [];

    foreach (identifierColumns() as [$table, $column]) {
        $before[$table . '.' . $column] = columnShapeOf($table, $column);
    }

    runNoPadMigration();

    /*
     * MySQL's MODIFY replaces the WHOLE definition, so naming a collation and
     * getting anything else wrong converts correctly and quietly changes what the
     * column accepts. Measured before this existed: a mutant declaring all eight
     * `null` instead of `not null` passed the entire suite, and so did one that
     * narrowed value from 255 to 64 -- which truncates on a host without strict
     * sql_mode, exactly the configuration this package documents as expected.
     */
    foreach (identifierColumns() as [$table, $column]) {
        $shape = columnShapeOf($table, $column);
        $width = str_contains($column, 'type') ? 32 : 255;

        expect($shape['type'])->toBe(sprintf('varchar(%d)', $width), sprintf('%s.%s width', $table, $column))
            ->and($shape['nullable'])->toBeFalse(sprintf('%s.%s must stay NOT NULL', $table, $column))
            ->and($shape)->toBe($before[$table . '.' . $column], sprintf('%s.%s shape', $table, $column));
    }
});

it('is safe to run twice', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL has a deterministic collation that pads.');
    }

    revertToPaddingCollation();
    runNoPadMigration();
    runNoPadMigration();

    foreach (identifierColumns() as [$table, $column]) {
        expect(comparesWithoutPadding($table, $column))->toBeTrue();
    }
});

it('changes no identifier rows', function (): void {
    if (skipUnlessMysql()) {
        $this->markTestSkipped('Only MySQL has a deterministic collation that pads.');
    }

    revertToPaddingCollation();

    /*
     * Rows that are NOT already canonical, which is the whole point. An earlier
     * version of this test seeded only 'ada@acme.example' -- lowercase, unpadded,
     * a fixed point of every transformation worth guarding against -- so a mutant
     * that ran `set value = lower(trim(trailing ' ' from value))` over all eight
     * columns while it had them open passed this test and the entire suite.
     *
     * These two are admissible together under the padding collation because they
     * differ in case, and neither survives a trim or a fold.
     */
    foreach (['ada@acme.example ', 'Ada@Acme.Example'] as $index => $value) {
        DB::table('auth_identifiers')->insert([
            'user_id' => $index + 1,
            'type' => 'email',
            'value' => $value,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /*
     * A collation change rewrites no bytes. An implementation that
     * re-canonicalized while it had the table open would change what an
     * identifier IS, which is a policy decision this issue deliberately does not
     * take -- trailing whitespace stays significant, consistently, on all three
     * engines.
     */
    runNoPadMigration();

    $stored = DB::table('auth_identifiers')->orderBy('user_id')->pluck('value')->all();

    expect(array_map(static fn (mixed $value): string => stringValue($value), $stored))
        ->toBe(['ada@acme.example ', 'Ada@Acme.Example'])
        ->and(DB::table('auth_identifiers')->count())->toBe(2);
});

it('leaves the other engines alone', function (): void {
    if (! skipUnlessMysql()) {
        $this->markTestSkipped('MySQL is the engine that carries the defect.');
    }

    /*
     * PostgreSQL does not pad varchar comparisons and SQLite compares bytes, so
     * there is nothing to install on either. Running it must still be harmless:
     * a migration that issued MySQL DDL unconditionally would break every
     * PostgreSQL and SQLite upgrade, and nothing else here would notice, because
     * every assertion above skips off MySQL.
     */
    runNoPadMigration();

    foreach (identifierColumns() as [$table, $column]) {
        expect(comparesWithoutPadding($table, $column))->toBeTrue()
            ->and(carriesDeterministicCollation($table, $column))
            ->toBe(DB::connection()->getDriverName() !== 'sqlite');
    }
});
