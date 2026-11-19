<?php

declare(strict_types=1);

use Fissible\Vouch\Support\IpThrottleLockBucket;
use Fissible\Vouch\Support\LockBucket;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/*
 * #16. The IP throttle's mutex, as a fixed set of keyed buckets.
 *
 * auth_throttle_ip_windows used to be its own mutex, so nothing could delete a
 * window and the table grew with every client IP ever seen. Taking this bucket
 * first makes a window ordinary state that vouch:prune reclaims once expired.
 *
 * Run before deploying code that reads it: an unseeded bucket refuses the lock.
 */
return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable(IpThrottleLockBucket::TABLE)) {
            Schema::create(IpThrottleLockBucket::TABLE, function (Blueprint $table): void {
                $table->unsignedInteger('bucket')->primary();
            });
        }

        LockBucket::seed(Schema::getConnection(), IpThrottleLockBucket::TABLE);
    }

    public function down(): void
    {
        Schema::dropIfExists(IpThrottleLockBucket::TABLE);
    }
};
