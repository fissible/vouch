<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_connections', function (Blueprint $table): void {
            $table->id();
            $table->string('tenant_id', 255)->nullable()->index();
            $table->string('email_domain', 255)->nullable()->index();
            $table->string('discovery_url', 512)->nullable();
            $table->string('client_id', 255)->nullable();
            $table->text('client_secret')->nullable();
            $table->json('claim_mappings')->nullable();
            $table->json('jit_rules')->nullable();

            // Both default false — parent spec §7.2 rules 2 and 3 require
            // per-connection opt-in. Trusting an IdP's email_verified claim or
            // auto-linking by default is how pre-account-hijacking works.
            $table->boolean('trust_email_verified')->default(false);
            $table->boolean('auto_link')->default(false);

            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_connections');
    }
};
