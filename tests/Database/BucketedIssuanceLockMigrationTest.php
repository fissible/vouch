<?php

declare(strict_types=1);

use Fissible\Vouch\Support\IssuanceLockBucket;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(DatabaseMigrations::class);

/*
 * #46, the upgrade path: an installation whose issuance mutex still holds a row
 * per submitted identifier.
 *
 * Nothing else reaches this migration. A fresh install gets the bucket table from
 * the creating migration, so by the time this one runs there is no
 * identifier_value column and it returns immediately -- which means the only
 * data-destroying statement in the change, a DROP TABLE, executes in no other
 * test. The shape it converts has to be built by hand, because no migration
 * produces it any more.
 *
 * DatabaseMigrations rather than RefreshDatabase: this is DDL, which commits on
 * MySQL whatever transaction wraps it, so a hand-built fixture has to be torn down
 * for real between tests.
 */

/** The upgrade migration, by the path the suite freezes. */
function runBucketedLockMigration(): void
{
    $migration = require dirname(__DIR__, 2)
        . '/database/migrations/2026_09_26_000001_bucketed_issuance_locks.php';

    /*
     * Narrowed rather than annotated: Migration declares no up(), so calling it on
     * the declared type is an error at level 9 and an inline annotation is
     * forbidden here.
     */
    if (! is_object($migration) || ! $migration instanceof Migration || ! is_callable([$migration, 'up'])) {
        throw new RuntimeException('The bucketed issuance lock migration did not return a migration.');
    }

    $migration->up();
}

/**
 * Rebuild the pre-#46 lock table: one row per submitted identifier.
 *
 * The state an upgrading host is actually in, and the only way to observe this
 * migration doing anything at all.
 */
function restoreIdentifierKeyedLocks(): void
{
    Schema::dropIfExists(IssuanceLockBucket::TABLE);

    Schema::create(IssuanceLockBucket::TABLE, function (Blueprint $table): void {
        $table->string('ceremony', 32);
        $table->string('identifier_type', 32);
        $table->string('identifier_value', 255);
        $table->unique(
            ['ceremony', 'identifier_type', 'identifier_value'],
            'auth_proof_issuance_locks_scope_unique',
        );
    });

    DB::table(IssuanceLockBucket::TABLE)->insert([
        ['ceremony' => 'recovery', 'identifier_type' => 'email', 'identifier_value' => 'ada@acme.example'],
        ['ceremony' => 'recovery', 'identifier_type' => 'email', 'identifier_value' => 'someone-who-never-registered@acme.example'],
        ['ceremony' => 'verification', 'identifier_type' => 'email', 'identifier_value' => 'grace@acme.example'],
    ]);
}

it('builds the shape it is meant to convert', function (): void {
    /*
     * The control. Every assertion below depends on the fixture really restoring
     * the identifier-keyed shape -- if it silently produced a bucket table, the
     * migration would return immediately and the conversion tests would pass
     * having converted nothing.
     */
    restoreIdentifierKeyedLocks();

    expect(Schema::hasColumn(IssuanceLockBucket::TABLE, 'identifier_value'))->toBeTrue()
        ->and(Schema::hasColumn(IssuanceLockBucket::TABLE, 'identifier_type'))->toBeTrue()
        ->and(Schema::hasColumn(IssuanceLockBucket::TABLE, 'bucket'))->toBeFalse()
        ->and(DB::table(IssuanceLockBucket::TABLE)->count())->toBe(3);
});

it('replaces identifier-keyed rows with the seeded bucket space', function (): void {
    restoreIdentifierKeyedLocks();

    runBucketedLockMigration();

    $buckets = DB::table(IssuanceLockBucket::TABLE)->orderBy('bucket')->pluck('bucket')->all();

    expect(Schema::hasColumn(IssuanceLockBucket::TABLE, 'identifier_value'))->toBeFalse()
        ->and(Schema::hasColumn(IssuanceLockBucket::TABLE, 'identifier_type'))->toBeFalse()
        ->and(Schema::hasColumn(IssuanceLockBucket::TABLE, 'bucket'))->toBeTrue()
        ->and(array_map(static fn (mixed $value): int => (int) stringValue($value), $buckets))
        ->toBe(range(0, IssuanceLockBucket::COUNT - 1));
});

it('retains no identifier that the old shape was holding', function (): void {
    restoreIdentifierKeyedLocks();

    runBucketedLockMigration();

    /*
     * The whole table rendered, not a named column: the reclamation this migration
     * performs is the point of the change, and a conversion that kept the strings
     * in some renamed column would satisfy a column-shaped assertion. The address
     * belonging to nobody is the one that matters -- it is the row a host had no
     * lawful reason to be storing and no way to remove.
     */
    $rendered = '';

    foreach (DB::table(IssuanceLockBucket::TABLE)->orderBy('bucket')->get() as $row) {
        $rendered .= json_encode($row, JSON_THROW_ON_ERROR);
    }

    foreach ([
        'ada@acme.example',
        'someone-who-never-registered',
        'grace@acme.example',
        'recovery',
        'verification',
    ] as $retained) {
        expect($rendered)->not->toContain($retained);
    }

    /*
     * A positive control on the rendering itself: an empty string contains none of
     * the above, so without this the assertions would hold for a table the
     * migration had simply emptied.
     */
    expect($rendered)->toContain('4095');
});

it('is safe to run twice', function (): void {
    restoreIdentifierKeyedLocks();

    runBucketedLockMigration();
    runBucketedLockMigration();

    /*
     * Row count only, and that is all this proves: a migration that dropped and
     * reseeded unconditionally ends with exactly these rows too, so this test
     * cannot tell a no-op from a rebuild. What distinguishes them is the test
     * below, which removes a row by hand and requires it to stay removed.
     */
    expect(DB::table(IssuanceLockBucket::TABLE)->count())->toBe(IssuanceLockBucket::COUNT)
        ->and(DB::table(IssuanceLockBucket::TABLE)->where('bucket', 0)->exists())->toBeTrue();
});

it('does nothing to an installation that already carries buckets', function (): void {
    /*
     * The no-op path, which is what every other test in the suite exercises
     * implicitly and none of them asserts. A migration that dropped and reseeded
     * regardless would be indistinguishable by row count, so this watches for the
     * DROP itself: a row written into the bucket table by hand survives a no-op and
     * does not survive a drop.
     */
    DB::table(IssuanceLockBucket::TABLE)->where('bucket', 0)->delete();

    runBucketedLockMigration();

    expect(DB::table(IssuanceLockBucket::TABLE)->where('bucket', 0)->exists())->toBeFalse()
        ->and(DB::table(IssuanceLockBucket::TABLE)->count())->toBe(IssuanceLockBucket::COUNT - 1);
});
