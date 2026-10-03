<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DateColumnsUpgrade;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;

/*
 * MySQL TIMESTAMP rejects the second after 2038-01-19 03:14:07. This reaches
 * created_at too, so eventually even inserting a row fails, independently of
 * configured lifetimes. Editing the originals protects fresh installations;
 * this separate migration reaches hosts that will never run those files again.
 */
return new class extends Migration
{
    public function up(): void
    {
        // Follow the migrator's connection, including migrate --database,
        // rather than resolving the application's default connection binding.
        $connection = Schema::getConnection();

        // PostgreSQL's timestamp already reaches beyond 2038 and SQLite stores
        // these dates as text. Neither needs MySQL's rebuild or UTC preflight.
        if ($connection->getDriverName() !== 'mysql') {
            return;
        }

        // The upgrade owns both discovery and DDL; the migration names neither
        // tables nor columns, so later package tables cannot escape its scope.
        (new DateColumnsUpgrade($connection))->apply();
    }

    /**
     * Deliberately empty: narrowing back to TIMESTAMP fails on any host that
     * has since stored a post-2038 value. Keeping DATETIME loses no data.
     */
    public function down(): void {}
};
