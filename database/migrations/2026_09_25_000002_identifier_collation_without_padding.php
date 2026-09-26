<?php

declare(strict_types=1);

use Fissible\Vouch\Identifiers\IdentifierEqualityUpgrade;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Schema;

/*
 * #63. Identifier equality stops depending on trailing whitespace too.
 *
 * #59 installed utf8mb4_bin, which is deterministic and PAD SPACE both: a query
 * for 'ada@x ' matched a stored 'ada@x', and unique(type, value) rejected the
 * padded spelling as a duplicate of the unpadded one. PostgreSQL's C and
 * SQLite's BINARY do neither, so trailing ASCII space remained exactly the
 * engine-dependent equality #59 set out to end -- and the check guarding it
 * asked for a name ending in `_bin`, which the padding collation satisfies.
 * IdentifierCanonicalizer normalizes case and Unicode but does not trim, so the
 * space reaches both the stored value and the lookup parameter and the engine
 * decides.
 *
 * Its own migration rather than an edit to #59's: a host that already ran that
 * one will never run it again. #59 now installs the NO PAD collation directly,
 * so a fresh installation never holds a padding one even transiently, and this
 * is a no-op there.
 *
 * Nothing here rewrites a row. Whether a trailing space ought to be trimmed is a
 * question about what an identifier IS, and is deliberately left alone: what this
 * settles is that the answer cannot depend on which database is installed.
 */
return new class extends Migration
{
    public function up(): void
    {
        $connection = Schema::getConnection();

        /*
         * MySQL is the only engine that can be carrying the defect, so it is the
         * only one with anything to install. Running the conversion's DDL on
         * PostgreSQL would rewrite four tables and rebuild their indexes to
         * arrive at the collation they already have.
         *
         * The connection comes from the migrator rather than the default
         * binding, matching #59, so this behaves the same on a host migrating a
         * non-default connection.
         */
        if ($connection->getDriverName() !== 'mysql') {
            return;
        }

        /*
         * The conversion owns the column list and the collation name; this names
         * neither. Two callers each naming the collation themselves is how the
         * padding one came to be installed by one of them.
         *
         * Idempotent: MODIFY states the whole definition, so a second run
         * restates the definition the column already has.
         */
        IdentifierEqualityUpgrade::installCollation($connection);
    }

    /**
     * Deliberately nothing.
     *
     * Tightening back to utf8mb4_bin fails outright on the installations this
     * most matters to: under PAD SPACE 'ada@x' and 'ada@x ' are one value, so
     * unique(type, value) rejects the conversion with 1062 Duplicate entry on any
     * host that has stored both spellings since. #59's rollback is empty for the
     * same class of reason. A rolled-back host loses nothing by keeping this
     * collation: values with no trailing whitespace compare identically under
     * either.
     */
    public function down(): void {}
};
