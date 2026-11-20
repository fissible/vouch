<?php

declare(strict_types=1);

use Fissible\Vouch\Support\LockBucket;
use Fissible\Vouch\Support\SubjectLockBucket;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * #17, the upgrade half: an install whose subject mutex still holds one row per
 * subject ever issued a token.
 *
 * Every existing row is discarded. A mutex is not a record, and those rows are
 * exactly the subject identities this change stops retaining. Dropped and
 * recreated, as #46 did, because the column, its unique index and the primary
 * key all change. Run with token issuance and credential changes paused: code
 * from the previous release writes the column this removes.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable(SubjectLockBucket::TABLE)
            || ! Schema::hasColumn(SubjectLockBucket::TABLE, 'subject_key')) {
            return;
        }

        Schema::drop(SubjectLockBucket::TABLE);

        Schema::create(SubjectLockBucket::TABLE, function (Blueprint $table): void {
            $table->unsignedInteger('bucket')->primary();
        });

        LockBucket::seed(Schema::getConnection(), SubjectLockBucket::TABLE);
    }

    /** Deliberately nothing: rolling back would mean inventing the subjects. */
    public function down(): void {}
};
