<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Amendment D to Phase 2.1 (spec 2026-08-12 §4).
 *
 * auth_challenges recorded attempt_id and factor_type and nothing about WHAT was
 * challenged. For OTP that is a hole: challenge() selects a verified identifier
 * and delivers a code to it, then verify() succeeds and must report a
 * SatisfiedFactor.credentialId. With no persisted target that credential is
 * chosen after the fact, so a user with OTP on two addresses could have a code
 * delivered to one and attributed to the other — and require_distinct_credentials
 * would then be keyed on something that never happened, while still passing.
 *
 * Nullable at the column, required for OTP at the application layer
 * (GuardsChallengeTarget): password and TOTP challenges have no delivery target,
 * so NOT NULL would be a lie.
 *
 * cascadeOnDelete, unlike Amendment A's restrictOnDelete: challenges are
 * ephemeral and swept, this is the credential's OWN deletion rather than an
 * identifier's, and an orphaned challenge is useless rather than historic.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_challenges', function (Blueprint $table): void {
            $table->foreignId('credential_id')->nullable()
                ->constrained('auth_credentials')
                ->cascadeOnDelete();
        });
    }

    public function down(): void
    {
        Schema::table('auth_challenges', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('credential_id');
        });
    }
};
