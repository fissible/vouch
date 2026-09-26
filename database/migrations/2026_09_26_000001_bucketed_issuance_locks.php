<?php

declare(strict_types=1);

use Fissible\Vouch\Support\IssuanceLockBucket;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * #46, the upgrade half: an installation whose issuance mutex still holds a row
 * per submitted identifier.
 *
 * Every existing row is discarded rather than rewritten. A mutex is not a record
 * of anything, so nothing in those rows is worth carrying forward -- and they are
 * exactly the attacker-chosen strings this change exists to stop retaining, so
 * dropping them is the reclamation path the previous shape never had.
 *
 * Its own migration rather than an edit to the creating one, matching #63: a host
 * that has already run that will never run it again.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable(IssuanceLockBucket::TABLE)
            || ! Schema::hasColumn(IssuanceLockBucket::TABLE, 'identifier_value')) {
            return;
        }

        /*
         * Dropped and recreated rather than altered. Every part of the shape
         * changes -- both identifier columns, the unique index over them, and a
         * primary key that was not there -- and SQLite cannot drop a column an
         * index names.
         */
        Schema::drop(IssuanceLockBucket::TABLE);

        Schema::create(IssuanceLockBucket::TABLE, function (Blueprint $table): void {
            $table->unsignedInteger('bucket')->primary();
        });

        IssuanceLockBucket::seed(Schema::getConnection());
    }

    /**
     * Deliberately nothing.
     *
     * Rolling back would mean inventing the identifiers the previous shape stored,
     * and an identifier-keyed table with no rows in it serializes nothing at all.
     */
    public function down(): void {}
};
