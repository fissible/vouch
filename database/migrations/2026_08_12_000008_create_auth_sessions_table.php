<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_sessions', function (Blueprint $table): void {
            $table->id();

            /*
             * HMAC-SHA256 of the host session ID, keyed to APP_KEY — never the
             * raw ID.
             *
             * Plain UNIQUE, not "unique among live rows": NULL != NULL in a
             * unique index on all three engines, so UNIQUE(binding, revoked_at)
             * would PERMIT multiple live rows per binding, which is the inverse
             * of the intent. Rotation updates the row in place instead.
             */
            $table->string('session_binding', 64)->unique();

            $table->unsignedBigInteger('user_id')->index();
            $table->json('amr');
            $table->string('acr', 64)->nullable();
            $table->json('assurance_facts')->nullable();

            // Oldest satisfied factor, for §5.3 recency checks.
            $table->timestamp('last_factor_at')->nullable();

            // Absolute, set at creation, never extended by activity.
            $table->timestamp('recovery_grace_expires_at')->nullable();

            $table->timestamp('revoked_at')->nullable()->index();
            $table->string('revoked_reason', 32)->nullable();

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_sessions');
    }
};
