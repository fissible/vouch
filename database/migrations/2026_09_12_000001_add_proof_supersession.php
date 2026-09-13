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
                $table->timestamp('superseded_at')->nullable()->index();
            });
        }

        // Proof rows cannot serialize the first issuance or an unknown identifier.
        // Keep an independent anchor, including after proof retention deletes rows.
        Schema::create('auth_proof_issuance_locks', function (Blueprint $table): void {
            $table->string('ceremony', 32);
            $table->string('identifier_type', 32);
            $table->string('identifier_value', 255);
            $table->unique(
                ['ceremony', 'identifier_type', 'identifier_value'],
                'auth_proof_issuance_locks_scope_unique',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_proof_issuance_locks');

        foreach (['auth_recovery_proofs', 'auth_identifier_verifications'] as $name) {
            Schema::table($name, function (Blueprint $table): void {
                $table->dropIndex(['superseded_at']);
                $table->dropColumn('superseded_at');
            });
        }
    }
};
