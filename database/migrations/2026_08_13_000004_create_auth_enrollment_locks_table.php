<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Serialization anchor for credential enrollment (spec 2026-08-12 §2).
 *
 * maxActiveCredentials() is count-then-insert, which is a read-modify-write:
 * two concurrent enrollments each observe capacity and each proceed. Row locks
 * alone cannot fix it — SELECT ... FOR UPDATE over auth_credentials locks the
 * rows that exist, and the first-enrollment race is precisely the case where
 * there are none. Hence a dedicated row per (user_id, type) that always exists
 * before the count is taken.
 *
 * No id, no timestamps: this is a mutex anchor, not a record. Rows are claimed
 * with insertOrIgnore, never deleted, and carry no state beyond their existence.
 *
 * user_id deliberately carries NO foreign key, unlike every other table here.
 * A mutex anchor must not cascade-delete with the user, and constraining it
 * would couple the acquire path — the hottest, most contended statement in
 * enrollment — to a lookup on the host's users table for a row that references
 * nothing and outlives nothing.
 *
 * A unique index rather than a composite primary key, because insertOrIgnore's
 * conflict behaviour was verified against this exact shape on SQLite, MySQL 8
 * and Postgres 16.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_enrollment_locks', function (Blueprint $table): void {
            $table->unsignedBigInteger('user_id');
            $table->string('type', 32);

            $table->unique(['user_id', 'type'], 'auth_enrollment_locks_user_type_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_enrollment_locks');
    }
};
