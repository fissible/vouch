<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_policies', function (Blueprint $table): void {
            $table->id();
            $table->string('tenant_id', 255)->nullable()->index();

            // Which intent this policy governs: login, step_up, enroll_factor, recover.
            $table->string('scope', 32);

            $table->json('document');

            // Defaults friendly. The strictest posture across all resolved
            // layers wins at resolution time (parent spec §7.1), so a
            // permissive default cannot loosen a stricter global floor.
            $table->string('posture', 16)->default('friendly');

            $table->timestamps();

            $table->unique(['tenant_id', 'scope']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_policies');
    }
};
