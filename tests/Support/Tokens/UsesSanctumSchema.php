<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tokens;

use Illuminate\Support\Facades\Schema;

/**
 * Loads Sanctum's OWN migration rather than a hand-rolled copy.
 *
 * A surrogate schema asserts compatibility against a fiction. The real one
 * differs in ways that matter to a driver: `name` is TEXT rather than a 255
 * VARCHAR, and `expires_at` carries an index. Reproducing it by hand means the
 * tests keep passing after Sanctum changes it, which is the opposite of what a
 * compatibility test is for.
 */
trait UsesSanctumSchema
{
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(dirname(__DIR__, 3) . '/vendor/laravel/sanctum/database/migrations');
    }

    protected function createTokenSubjectTables(): void
    {
        Schema::create('token_users', function ($table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->timestamps();
        });

        // A subject that does NOT use HasApiTokens. Sanctum refuses to
        // authenticate one (Guard::supportsTokens), and the driver must not
        // claim it either.
        Schema::create('plain_users', function ($table): void {
            $table->id();
            $table->string('name')->nullable();
            $table->timestamps();
        });
    }
}
