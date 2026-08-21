<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Durable, TTL-bounded OTP delivery state.
 *
 * auth_challenges keeps only the verification digest. The exact code and
 * delivery target must survive queue retries, but are live credentials and may
 * not be stored in plaintext. The model therefore encrypts payload and hides
 * it from every serialization route; success, permanent failure, and expiry
 * clear it immediately.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_challenges', function (Blueprint $table): void {
            $table->boolean('is_decoy')->default(false);
        });

        Schema::create('auth_challenge_outbox', function (Blueprint $table): void {
            $table->id();
            $table->char('opaque_id', 64)->unique();
            $table->foreignId('challenge_id')
                ->constrained('auth_challenges')
                ->cascadeOnDelete();
            $table->text('payload')->nullable();
            $table->string('status', 32);
            $table->timestamp('expires_at')->index();
            $table->timestamp('dispatched_at')->nullable()->index();
            $table->timestamp('provider_attempted_at')->nullable();
            $table->timestamp('delivered_at')->nullable();
            $table->timestamp('undeliverable_at')->nullable();
            $table->timestamps();

            $table->index(
                ['status', 'expires_at'],
                'auth_challenge_outbox_pending_expiry_index',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_challenge_outbox');

        Schema::table('auth_challenges', function (Blueprint $table): void {
            $table->dropColumn('is_decoy');
        });
    }
};
