<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_credentials', function (Blueprint $table): void {
            $table->id();
            $table->unsignedBigInteger('user_id')->index();

            // Open string, not an enum: drivers register their own type keys in 2.2.
            $table->string('type', 32);

            // WebAuthn origin binding (parent spec §4.1). Null for origin-free
            // credentials such as passwords and TOTP secrets.
            $table->string('relying_party_id', 255)->nullable();

            $table->text('secret')->nullable();
            $table->string('strength', 32);

            // §3.6 satisfiability attributes. Every one defaults false — the
            // fail-closed direction. A credential defaulting to
            // phishing_resistant = true would satisfy a high-assurance policy
            // it has no business satisfying.
            $table->boolean('is_multi_factor')->default(false);
            $table->boolean('user_verified')->default(false);
            $table->boolean('phishing_resistant')->default(false);
            $table->string('authenticator_id', 255)->nullable();

            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('disabled_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'type']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_credentials');
    }
};
