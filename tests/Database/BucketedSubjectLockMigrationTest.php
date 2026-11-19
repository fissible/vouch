<?php

declare(strict_types=1);

use Fissible\Vouch\Support\LockBucket;
use Fissible\Vouch\Support\SubjectLockBucket;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(DatabaseMigrations::class);

/*
 * #17, the upgrade path: an installation whose subject mutex still holds one row
 * per subject ever issued a token.
 *
 * A fresh install gets the bucket table from the creating migration, so only a
 * hand-built fixture reaches the DROP this migration performs. DatabaseMigrations
 * because DDL commits on MySQL whatever transaction wraps it.
 */

function runBucketedSubjectLockMigration(): void
{
    $migration = require dirname(__DIR__, 2)
        . '/database/migrations/2026_11_20_000001_bucketed_subject_locks.php';

    if (! is_object($migration) || ! $migration instanceof Migration || ! is_callable([$migration, 'up'])) {
        throw new RuntimeException('The bucketed subject lock migration did not return a migration.');
    }

    $migration->up();
}

/** Rebuild the pre-#17 table: one anchor row per subject, keyed "provider:id". */
function restoreSubjectKeyedLocks(): void
{
    Schema::dropIfExists(SubjectLockBucket::TABLE);

    Schema::create(SubjectLockBucket::TABLE, function (Blueprint $table): void {
        $table->string('subject_key');
        $table->unique('subject_key', 'auth_subject_locks_subject_key_unique');
    });

    DB::table(SubjectLockBucket::TABLE)->insert([
        ['subject_key' => 'App\\Models\\User:7'],
        ['subject_key' => 'App\\Models\\User:deleted-long-ago'],
    ]);
}

/** @return list<int> */
function subjectLockBuckets(): array
{
    return array_map(
        static fn (mixed $bucket): int => is_numeric($bucket) ? (int) $bucket : -1,
        DB::table(SubjectLockBucket::TABLE)->orderBy('bucket')->pluck('bucket')->all(),
    );
}

it('builds the shape it is meant to convert', function (): void {
    restoreSubjectKeyedLocks();

    expect(Schema::hasColumn(SubjectLockBucket::TABLE, 'subject_key'))->toBeTrue()
        ->and(Schema::hasColumn(SubjectLockBucket::TABLE, 'bucket'))->toBeFalse()
        ->and(DB::table(SubjectLockBucket::TABLE)->count())->toBe(2);
});

it('replaces subject-keyed rows with the seeded bucket space and keeps no subject', function (): void {
    restoreSubjectKeyedLocks();

    runBucketedSubjectLockMigration();

    $rendered = json_encode(DB::table(SubjectLockBucket::TABLE)->get()->all(), JSON_THROW_ON_ERROR);

    expect(Schema::hasColumn(SubjectLockBucket::TABLE, 'subject_key'))->toBeFalse()
        ->and(subjectLockBuckets())->toBe(range(0, LockBucket::COUNT - 1))
        ->and($rendered)->not->toContain('deleted-long-ago')
        ->and($rendered)->not->toContain('Models')
        // Control: the rendering is the full table, not an empty string.
        ->and($rendered)->toContain('4095');
});

it('is safe to run twice', function (): void {
    restoreSubjectKeyedLocks();

    runBucketedSubjectLockMigration();
    runBucketedSubjectLockMigration();

    expect(subjectLockBuckets())->toBe(range(0, LockBucket::COUNT - 1));
});

it('does nothing to an installation that already carries buckets', function (): void {
    // A row removed by hand survives a no-op and would not survive a rebuild.
    DB::table(SubjectLockBucket::TABLE)->where('bucket', 0)->delete();

    runBucketedSubjectLockMigration();

    expect(DB::table(SubjectLockBucket::TABLE)->where('bucket', 0)->exists())->toBeFalse()
        ->and(DB::table(SubjectLockBucket::TABLE)->count())->toBe(LockBucket::COUNT - 1);
});
