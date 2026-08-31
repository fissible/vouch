<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('auth_sessions')) {
            return;
        }

        Schema::table('auth_sessions', function (Blueprint $table): void {
            $table->json('assurance_proof')->nullable();
            $table->renameColumn('last_factor_at', 'weakest_satisfied_at');
            $table->dropColumn('assurance_facts');
        });
    }

    public function down(): void
    {
        if (! Schema::hasTable('auth_sessions')) {
            return;
        }

        Schema::table('auth_sessions', function (Blueprint $table): void {
            $table->json('assurance_facts')->nullable();
            $table->renameColumn('weakest_satisfied_at', 'last_factor_at');
            $table->dropColumn('assurance_proof');
        });
    }
};
