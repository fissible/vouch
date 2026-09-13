<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        foreach (['auth_recovery_proofs', 'auth_identifier_verifications'] as $name) {
            Schema::table($name, function (Blueprint $table): void {
                $table->unsignedInteger('attempts')->default(0);
                // Burning is evidence of exhausted guesses, never redemption.
                $table->timestamp('burned_at')->nullable()->index();
            });
        }
    }

    public function down(): void
    {
        foreach (['auth_recovery_proofs', 'auth_identifier_verifications'] as $name) {
            Schema::table($name, function (Blueprint $table): void {
                $table->dropIndex(['burned_at']);
                $table->dropColumn(['attempts', 'burned_at']);
            });
        }
    }
};
