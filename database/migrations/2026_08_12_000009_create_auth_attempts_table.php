<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_attempts', function (Blueprint $table): void {
            $table->id();

            // The opaque handle the client holds. Attempt state itself is never
            // trusted from the client (parent spec §3.4).
            $table->string('handle', 64)->unique();

            $table->string('state', 32);

            // Monotonic, incremented on every transition. The CAS predicate.
            $table->unsignedBigInteger('version')->default(1);

            $table->string('tenant_id', 255)->nullable()->index();
            $table->string('identifier', 255)->nullable();
            $table->unsignedBigInteger('user_id')->nullable()->index();

            // Session/browser context the attempt was created under. A
            // transition presented from a different context is refused.
            $table->string('bound_context', 255)->nullable();

            $table->json('satisfied_factors')->nullable();
            $table->timestamp('expires_at')->index();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_attempts');
    }
};
