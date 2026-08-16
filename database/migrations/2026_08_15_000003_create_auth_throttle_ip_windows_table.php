<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Persistent serialization parent for one canonical IP bucket.
 *
 * The first marker in a new bucket serializes on the unique insert. Every later
 * marker serializes by locking this committed row before checking or rolling its
 * database-clock window. The parent intentionally survives marker pruning: if it
 * were deleted, production would repeatedly fall back to the easier absent-row
 * race and PostgreSQL's committed-row FOR UPDATE path would go unexercised.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_throttle_ip_windows', function (Blueprint $table): void {
            $table->id();
            $table->string('dimension', 32);
            $table->char('ip_digest', 64);
            $table->timestamp('window_started_at');
            $table->timestamp('created_at');
            $table->timestamp('updated_at');

            $table->unique(
                ['dimension', 'ip_digest'],
                'auth_throttle_ip_window_subject_unique',
            );
            $table->index('window_started_at', 'auth_throttle_ip_window_start_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_throttle_ip_windows');
    }
};
