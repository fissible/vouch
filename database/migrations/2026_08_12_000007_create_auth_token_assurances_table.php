<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_token_assurances', function (Blueprint $table): void {
            $table->id();

            /*
             * References personal_access_tokens.id. Declared as a plain indexed
             * column rather than a foreign key because Sanctum's table may not
             * exist when vouch migrates, and vouch does not own its schema.
             * Phase 2.4 adds the cascade-delete behaviour in application code.
             *
             * Unique: one assurance record per token. A token with two records
             * would let a reader pick whichever assurance suited it.
             */
            $table->unsignedBigInteger('token_id')->unique();

            $table->string('acr', 64);
            $table->json('amr');
            $table->json('credential_ids');
            $table->string('issuing_session_id', 255)->index();
            $table->timestamp('issued_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_token_assurances');
    }
};
