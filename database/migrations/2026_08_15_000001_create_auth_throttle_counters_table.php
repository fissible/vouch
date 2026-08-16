<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Current fixed-window scalar state for authentication throttle dimensions.
 *
 * A row identifies its subject only by a domain-separated HMAC digest. The host
 * cannot recover an identifier, tenant, or other subject from this table, and
 * no user foreign key turns unknown-identifier counting into an existence
 * oracle. Window rollover updates this row atomically; history belongs to the
 * future audit chain, not to the online throttle.
 *
 * There is deliberately no default for count or either timestamp. The store
 * owns every write and uses the database clock for the window and operational
 * timestamps, so a schema default would be a second, engine-specific writer.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_throttle_counters', function (Blueprint $table): void {
            $table->id();
            $table->string('dimension', 32);
            $table->char('subject_digest', 64);
            $table->timestamp('window_started_at');
            $table->unsignedBigInteger('count');
            $table->timestamp('created_at');
            $table->timestamp('updated_at');

            $table->unique(
                ['dimension', 'subject_digest'],
                'auth_throttle_counter_subject_unique',
            );
            $table->index('window_started_at', 'auth_throttle_counter_window_index');
            $table->index('updated_at', 'auth_throttle_counter_updated_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_throttle_counters');
    }
};
