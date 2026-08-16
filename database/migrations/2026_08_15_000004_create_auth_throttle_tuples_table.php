<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Distinct submitted-identifier markers for an IP bucket and fixed window.
 *
 * This is not a failure counter. One tuple digest contributes at most once per
 * exact parent generation, so repeated mistakes against one identifier do not
 * resemble breadth across many identifiers. COUNT over the unique index is the
 * value; no affected-row result or denormalized integer becomes a portability
 * premise. Markers expire after their window while the parent persists.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_throttle_tuples', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('ip_window_id')
                ->constrained('auth_throttle_ip_windows')
                ->cascadeOnDelete();
            $table->timestamp('window_started_at');
            $table->char('tuple_digest', 64);
            $table->timestamp('created_at');
            $table->timestamp('updated_at');

            /*
             * Besides enforcing uniqueness, this ordering is the indexed COUNT
             * path: (ip_window_id, window_started_at) is its leftmost prefix.
             */
            $table->unique(
                ['ip_window_id', 'window_started_at', 'tuple_digest'],
                'auth_throttle_tuple_window_unique',
            );
            $table->index('window_started_at', 'auth_throttle_tuple_prune_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_throttle_tuples');
    }
};
