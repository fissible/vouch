<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_identifier_verifications', function (Blueprint $table): void {
            $table->id();
            $table->string('identifier_type', 32);
            $table->string('identifier_value', 255);
            $table->string('code_hash');
            $table->boolean('is_decoy')->default(false);
            $table->dateTime('expires_at')->index();
            $table->dateTime('consumed_at')->nullable()->index();
            $table->datetimes();

            $table->index(
                ['identifier_type', 'identifier_value', 'consumed_at'],
                'auth_identifier_verifications_redemption_index',
            );
        });

        Schema::create('auth_identifier_verification_outbox', function (Blueprint $table): void {
            $table->id();
            $table->char('opaque_id', 64)->unique();
            $table->foreignId('verification_id')
                ->constrained('auth_identifier_verifications')
                ->cascadeOnDelete();
            $table->text('payload')->nullable();
            $table->string('status', 32);
            $table->dateTime('expires_at')->index();
            $table->dateTime('dispatched_at')->nullable()->index();
            $table->dateTime('provider_attempted_at')->nullable();
            $table->dateTime('delivered_at')->nullable();
            $table->dateTime('undeliverable_at')->nullable();
            $table->string('failure_reason', 64)->nullable();
            $table->datetimes();

            $table->index(
                ['status', 'expires_at'],
                'auth_identifier_verification_outbox_pending_expiry_index',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_identifier_verification_outbox');
        Schema::dropIfExists('auth_identifier_verifications');
    }
};
