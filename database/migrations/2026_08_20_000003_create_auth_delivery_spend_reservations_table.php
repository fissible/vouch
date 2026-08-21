<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_delivery_spend_reservations', function (Blueprint $table): void {
            $table->id();
            $table->char('reservation_key', 64);
            $table->string('scope', 16);
            $table->unsignedBigInteger('amount_minor');
            $table->timestamp('created_at');

            $table->index('created_at', 'auth_delivery_spend_reservations_created_at_index');

            $table->unique(
                ['reservation_key', 'scope'],
                'auth_delivery_spend_reservations_key_scope_unique',
            );
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_delivery_spend_reservations');
    }
};
