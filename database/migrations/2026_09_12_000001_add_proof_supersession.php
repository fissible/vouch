<?php

declare(strict_types=1);

use Fissible\Vouch\Support\IssuanceLockBucket;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        foreach (['auth_recovery_proofs', 'auth_identifier_verifications'] as $name) {
            if (Schema::hasColumn($name, 'superseded_at')) {
                continue;
            }

            Schema::table($name, function (Blueprint $table): void {
                $table->dateTime('superseded_at')->nullable()->index();
            });
        }

        /*
         * Proof rows cannot serialize the first issuance or an unknown identifier,
         * so the mutex needs an anchor of its own that survives proof retention.
         *
         * #46: that anchor is a BUCKET rather than the submitted string. The rows
         * are a fixed set seeded here, so the table never grows with caller input
         * and retains no identifier -- and with nothing retained there is nothing
         * to reclaim, so no deletion protocol has to be proved safe against a
         * concurrent holder. The ceremony is folded into the hashed message rather
         * than stored as a column, so one bucket space serves both ceremonies.
         */
        if (! Schema::hasTable(IssuanceLockBucket::TABLE)) {
            Schema::create(IssuanceLockBucket::TABLE, function (Blueprint $table): void {
                // The bucket IS the key: one row per bucket, seeded below and only
                // ever locked, never inserted at issuance time.
                $table->unsignedInteger('bucket')->primary();
            });
        }

        IssuanceLockBucket::seed(Schema::getConnection());
    }

    public function down(): void
    {
        Schema::dropIfExists(IssuanceLockBucket::TABLE);

        foreach (['auth_recovery_proofs', 'auth_identifier_verifications'] as $name) {
            Schema::table($name, function (Blueprint $table): void {
                $table->dropIndex(['superseded_at']);
                $table->dropColumn('superseded_at');
            });
        }
    }
};
