<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Amendment B to Phase 2.1 (spec 2026-08-12 §4).
 *
 * RFC 6238 §5.2 requires that an accepted OTP not be accepted a second time,
 * and a wall-clock last_used_at cannot recover WHICH timestep was accepted once
 * a leeway window is allowed: a code from timestep T+1 can be accepted while the
 * wall clock sits in period T, so deriving the timestep from last_used_at yields
 * T, and replaying the T+1 code passes a `>` check again. The guard would look
 * correct and permit the exact replay the RFC forbids.
 *
 * last_used_at remains operational metadata. It is not the security guard.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            $table->unsignedBigInteger('last_used_timestep')->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            $table->dropColumn('last_used_timestep');
        });
    }
};
