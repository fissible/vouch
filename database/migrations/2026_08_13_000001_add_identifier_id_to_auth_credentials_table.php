<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Amendment A to Phase 2.1 (spec 2026-08-12 §4).
 *
 * OTP credentials must reference the address they deliver to. The kernel's
 * require_distinct_credentials keys on credentialId, so a factor with no
 * credential cannot participate in distinctness — OTP therefore needs credential
 * rows, and their identity IS the destination address. Overloading
 * authenticator_id would corrupt require_independent_authenticators, which
 * consumes it for a different purpose.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            /*
             * restrictOnDelete, not cascade. An address that ever served as an
             * authentication destination is permanent audit history. This blocks
             * deletion regardless of disabled_at, so "disabled, therefore
             * deletable" is FALSE — there is no retirement workflow in v1.
             */
            $table->foreignId('identifier_id')->nullable()
                ->constrained('auth_identifiers')
                ->restrictOnDelete();

            /*
             * NULL semantics here are the INVERSE of the 2.1 session-binding
             * case, and this looks like the mistake that was just fixed. It is
             * not. There, NULL != NULL broke the constraint by permitting
             * multiple live rows. Here it is exactly what is wanted: OTP
             * credentials always carry a non-null identifier_id and are
             * constrained to one per address; password, TOTP, recovery and
             * passkey rows carry NULL and are bounded by maxActiveCredentials()
             * instead, enforced by EnrollmentGuard rather than by this index.
             *
             * Explicit index name: the generated one would be
             * auth_credentials_user_id_type_identifier_id_unique, and 2.1 set the
             * precedent of naming composite indexes rather than relying on
             * generation near MySQL's 64-character limit.
             */
            $table->unique(['user_id', 'type', 'identifier_id'], 'auth_cred_user_type_ident_unique');
        });
    }

    public function down(): void
    {
        Schema::table('auth_credentials', function (Blueprint $table): void {
            $table->dropUnique('auth_cred_user_type_ident_unique');
            $table->dropConstrainedForeignId('identifier_id');
        });
    }
};
