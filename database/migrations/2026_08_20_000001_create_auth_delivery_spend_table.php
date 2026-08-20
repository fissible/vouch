<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_delivery_spend', function (Blueprint $table): void {
            $table->id();
            $table->string('scope', 16);
            $table->char('subject_digest', 64);
            $table->timestamp('window_started_at');
            $table->unsignedBigInteger('spent_minor');
            $table->timestamp('created_at');
            $table->timestamp('updated_at');

            $table->unique(['scope', 'subject_digest'], 'auth_delivery_spend_subject_unique');
            $table->index('window_started_at', 'auth_delivery_spend_window_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_delivery_spend');
    }
};
