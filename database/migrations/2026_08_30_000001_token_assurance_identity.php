<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        Schema::dropIfExists('auth_token_credentials');
        Schema::dropIfExists('auth_token_assurances');

        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            DB::statement("CREATE TABLE auth_token_assurances (
                id integer primary key autoincrement,
                issuer_key varchar(64) not null check (issuer_key <> ''),
                token_key varchar(191) not null check (token_key <> ''),
                subject_key varchar(255) not null,
                tenant_id varchar(255) null,
                actor_kind varchar(16) not null,
                acr varchar(64) null,
                assurance_proof text null,
                weakest_satisfied_at datetime null,
                created_at datetime null,
                updated_at datetime null
            )");
        } else {
            Schema::create('auth_token_assurances', function (Blueprint $table): void {
            $table->id();
            $table->string('issuer_key', 64);
            $table->string('token_key', 191);
            $table->string('subject_key', 255);
            $table->string('tenant_id', 255)->nullable();
            $table->string('actor_kind', 16);
            $table->string('acr', 64)->nullable();
            $table->json('assurance_proof')->nullable();
            $table->timestamp('weakest_satisfied_at')->nullable();
            $table->timestamps();
            });
            DB::statement("ALTER TABLE auth_token_assurances ADD CONSTRAINT auth_token_assurance_issuer_not_empty CHECK (issuer_key <> '')");
            DB::statement("ALTER TABLE auth_token_assurances ADD CONSTRAINT auth_token_assurance_token_not_empty CHECK (token_key <> '')");
        }
        Schema::table('auth_token_assurances', function (Blueprint $table): void {
            $table->unique(['issuer_key', 'token_key'], 'auth_token_assurance_identity_unique');
            $table->index(['subject_key', 'actor_kind'], 'auth_token_assurance_subject_index');
            $table->index('weakest_satisfied_at', 'auth_token_assurance_recency_index');
        });

        if (Schema::getConnection()->getDriverName() === 'sqlite') {
            DB::statement("CREATE TABLE auth_token_credentials (
                id integer primary key autoincrement,
                issuer_key varchar(64) not null check (issuer_key <> ''),
                token_key varchar(191) not null check (token_key <> ''),
                credential_id varchar(191) not null check (credential_id <> '')
            )");
        } else {
            Schema::create('auth_token_credentials', function (Blueprint $table): void {
            $table->id();
            $table->string('issuer_key', 64);
            $table->string('token_key', 191);
            $table->string('credential_id', 191);
            });
            DB::statement("ALTER TABLE auth_token_credentials ADD CONSTRAINT auth_token_credential_issuer_not_empty CHECK (issuer_key <> '')");
            DB::statement("ALTER TABLE auth_token_credentials ADD CONSTRAINT auth_token_credential_token_not_empty CHECK (token_key <> '')");
            DB::statement("ALTER TABLE auth_token_credentials ADD CONSTRAINT auth_token_credential_id_not_empty CHECK (credential_id <> '')");
        }
        Schema::table('auth_token_credentials', function (Blueprint $table): void {
            $table->unique(['issuer_key', 'token_key', 'credential_id'], 'auth_token_credential_unique');
            $table->index('credential_id', 'auth_token_credential_lookup_index');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('auth_token_credentials');
        Schema::dropIfExists('auth_token_assurances');
    }
};
