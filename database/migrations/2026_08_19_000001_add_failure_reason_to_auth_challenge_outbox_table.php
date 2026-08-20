<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_challenge_outbox', function (Blueprint $table): void {
            // Nullable preserves redacted history created before 2.3c.
            $table->string('failure_reason', 32)->nullable()->index();
        });
    }

    public function down(): void
    {
        Schema::table('auth_challenge_outbox', function (Blueprint $table): void {
            $table->dropColumn('failure_reason');
        });
    }
};
