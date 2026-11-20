<?php

declare(strict_types=1);

use Fissible\Vouch\Support\LockBucket;
use Fissible\Vouch\Support\SubjectLockBucket;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Durable serialization for provider-qualified subject operations.
 *
 * Subject-wide token work can run after every session has gone away, so a
 * session row cannot be its mutex. Since #17 the table is a fixed set of keyed
 * buckets, seeded here, so a fresh install never holds the per-subject shape.
 * An install that already ran this gets the conversion from
 * 2026_11_20_000001_bucketed_subject_locks.
 *
 * There is deliberately no foreign key: a mutex must not cascade-delete with a
 * host user, nor couple the most contended statement to a host lookup.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(SubjectLockBucket::TABLE, function (Blueprint $table): void {
            $table->unsignedInteger('bucket')->primary();
        });

        LockBucket::seed(Schema::getConnection(), SubjectLockBucket::TABLE);
    }

    public function down(): void
    {
        Schema::dropIfExists(SubjectLockBucket::TABLE);
    }
};
