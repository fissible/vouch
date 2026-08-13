<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('auth_federated_identities', function (Blueprint $table): void {
            $table->id();

            // NOT NULL by design: a federated identity untethered from a
            // connection would be usable across tenants (parent spec §7.2).
            $table->foreignId('connection_id')
                ->constrained('auth_connections')
                ->cascadeOnDelete();

            /*
             * 255, not 512. This column is part of the unique index below, and
             * MySQL/InnoDB caps a key at 3072 bytes. Under utf8mb4 at 4 bytes
             * per character, 512 + 255 + a bigint comes to 3076 — four bytes
             * over, and the migration fails outright, making the package
             * uninstallable on MySQL. SQLite has no such limit and cannot
             * surface this; the cross-engine matrix caught it on its first run.
             *
             * 255 is ample for an OIDC issuer identifier, which is a URL —
             * every mainstream IdP is well under 100 characters. discovery_url
             * on auth_connections stays 512 because it is not indexed.
             */
            $table->string('issuer', 255);
            $table->string('subject', 255);
            $table->json('claims')->nullable();
            $table->unsignedBigInteger('user_id')->nullable()->index();
            $table->timestamps();

            /*
             * The identity key is (connection, issuer, subject) — never email,
             * which is mutable at the IdP. Enforced here as a database
             * constraint rather than a driver convention, because parent spec
             * §7.2 rule 1 is a cross-tenant account-takeover guard and
             * conventions are not enforcement.
             *
             * The index name is explicit: the generated one exceeds MySQL's
             * 64-character identifier limit.
             */
            $table->unique(['connection_id', 'issuer', 'subject'], 'auth_fedid_conn_iss_sub_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_federated_identities');
    }
};
