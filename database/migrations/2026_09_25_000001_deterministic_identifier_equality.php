<?php

declare(strict_types=1);

use Fissible\Vouch\Identifiers\IdentifierEqualityUpgrade;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;

/*
 * #59. Identifier equality stops depending on which engine is installed: the
 * columns get a deterministic collation and the canonical form is what is
 * stored. Rows that disagree with that are triaged first, and a collision only
 * a human can settle refuses the whole upgrade rather than converting half of it.
 *
 * IdentifierEqualityUpgrade carries the work, and the reasoning with it. The
 * connection comes from the migrator rather than the default binding, so this
 * behaves the same when a host migrates a non-default connection.
 */
return new class extends Migration
{
    public function up(): void
    {
        (new IdentifierEqualityUpgrade(
            Schema::getConnection(),
            app(IdentifierCanonicalizer::class),
        ))->apply();
    }

    /**
     * Deliberately nothing.
     *
     * Neither half of this migration has an inverse. Case folding and
     * normalization cannot be undone, and restoring a looser collation can
     * violate the unique indexes outright -- rows that only byte equality keeps
     * apart are exactly what an accent-insensitive index rejects, so a revert
     * fails on the installations most in need of one. Leaving the deterministic
     * collation in place costs a rolled-back host nothing: its rows are already
     * canonical, and canonical rows compare identically under either collation.
     */
    public function down(): void {}
};
