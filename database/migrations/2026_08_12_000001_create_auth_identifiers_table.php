<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_identifiers', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();
            $table->string('type', 32);
            $table->string('value', 255);
            $table->timestamp('verified_at')->nullable();
            $table->boolean('is_primary')->default(false);
            $table->timestamps();

            $table->unique(['type', 'value']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_identifiers');
    }
};
