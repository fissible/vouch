<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_challenges', function (Blueprint $table): void {
            $table->id();
            $table->foreignId('attempt_id')
                ->constrained('auth_attempts')
                ->cascadeOnDelete();

            $table->string('factor_type', 32);

            // Hashed, never plaintext (parent spec §7.6). There is deliberately
            // no `code` column: one cannot leak what does not exist.
            $table->string('code_hash', 128);

            $table->unsignedInteger('attempts')->default(0);
            $table->string('bound_ip', 45)->nullable();
            $table->string('bound_user_agent', 512)->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamp('consumed_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_challenges');
    }
};
