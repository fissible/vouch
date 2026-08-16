<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Submitted-identifier lock state, separate from failure counters.
 *
 * Only the identifier writer may create this row. Recovery and every shared
 * dimension can derive backoff but have no table through which to acquire lock
 * authority. Keeping the deadline separate also prevents strict-posture code
 * from reading attempts remaining merely because it needs locked_until.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_throttle_locks', function (Blueprint $table): void {
            $table->id();
            $table->char('subject_digest', 64)->unique('auth_throttle_lock_subject_unique');
            $table->timestamp('locked_until');
            $table->timestamp('created_at');
            $table->timestamp('updated_at');

            $table->index('locked_until', 'auth_throttle_lock_deadline_index');
            $table->index('updated_at', 'auth_throttle_lock_updated_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_throttle_locks');
    }
};
