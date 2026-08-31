<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Durable serialization anchor for provider-qualified subject operations.
 *
 * Subject-wide token work can run after every session has gone away, so a
 * session row cannot be its mutex. This permanent anchor is claimed before it
 * is locked, making the empty-subject case serialize just like an established
 * subject. Its key is SubjectKey's canonical provider:id form, preserving both
 * identity halves and string-distinct identifiers.
 *
 * This table intentionally has no id or timestamps: it represents only the
 * continued availability of a mutex row. Acquirers use insertOrIgnore and do
 * not delete it, so neither a lifecycle identity nor audit timestamps describe
 * meaningful state.
 *
 * There is deliberately no foreign key. The anchor must remain independent of
 * host user/session deletion, and enforcing a host lookup on the contention
 * path would turn a standalone lock acquisition into coupled domain work.
 *
 * A unique index supplies the conflict behaviour required by insertOrIgnore;
 * a primary key is unnecessary because the value is a serialization anchor,
 * not an entity identity exposed to application code.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_subject_locks', function (Blueprint $table): void {
            $table->string('subject_key');
            $table->unique('subject_key', 'auth_subject_locks_subject_key_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_subject_locks');
    }
};
