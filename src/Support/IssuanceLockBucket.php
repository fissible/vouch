<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Support\Facades\Config;
use RuntimeException;

/**
 * #46. Which mutex row one issuance scope takes.
 *
 * The issuance mutex needs an anchor that exists before the first proof does and
 * outlives proof retention, and #38 gave it one per submitted identifier. That
 * made the table grow with attacker-chosen input and retain an arbitrary address
 * forever. A mutex does not need to know what it protects: hashing the scope into
 * a fixed set of buckets keeps the serialization and discards the identity, which
 * removes the retention question instead of managing it.
 *
 * The cost is false sharing -- two unrelated identifiers in one bucket serialize
 * against each other for the length of one issuance transaction. That is latency,
 * not a failure, and it must never move state between the two.
 *
 * WHICH INPUTS SHARE A BUCKET IS THE CANONICAL FORM'S ANSWER. That is only safe
 * to say since #59 and #63: the identifier columns carry a deterministic NO PAD
 * collation over canonical values, so SQL equality IS equality of canonical forms
 * on all three engines, and hashing the canonical form agrees with the
 * supersession predicate by construction. Two earlier attempts -- an accent fold,
 * then an ICU primary-strength key -- failed because the COLUMN decided identity
 * and the bucket had to predict it.
 *
 * Keyed, because an unkeyed mapping lets a caller work out which bucket an
 * identifier lands in and aim traffic at it, turning false sharing into a denial
 * of service. A key-dependent offset over an unkeyed hash is not enough either:
 * it moves every bucket while preserving which pairs collide, so a colliding pair
 * found once stays one forever.
 *
 * Keyed on a DEDICATED secret rather than on APP_KEY. Rotating APP_KEY
 * invalidates sessions and attempts and is expected to be survivable; if it also
 * remapped every bucket then, for the length of any rollout, old and new
 * processes would derive different mutexes for one identifier and stop
 * serializing it. Rotating THIS secret has that cost, so it needs a coordinated
 * deployment.
 */
final class IssuanceLockBucket
{
    /**
     * Buckets the migration seeds, and the modulus of the derivation.
     *
     * With C simultaneous distinct issuances an arriving request shares a bucket
     * with probability about (C-1)/4096, so ten at once contend roughly one
     * request in 455 -- at the cost of one issuance transaction, not a failure.
     * Four thousand rows of one small column is nothing to store, and raising it
     * buys less than it costs: the count is part of the derivation, so changing it
     * moves every scope's bucket at once.
     */
    public const COUNT = 4096;

    /** Named once, because the refusal quotes it and the provider validates it. */
    public const SECRET_KEY = 'vouch.issuance_locks.secret';

    /** The table the buckets are rows of. */
    public const TABLE = 'auth_proof_issuance_locks';

    /** Rows per insert statement while seeding. */
    private const SEED_CHUNK = 512;

    /**
     * Domain label, so this HMAC cannot be confused with any other the package
     * derives even if one ever shared the secret.
     */
    private const DOMAIN = 'issuance.mutex';

    /**
     * The shortest secret this accepts, in bytes.
     *
     * hash_hmac takes a one-character key without complaint, so without a floor
     * `VOUCH_ISSUANCE_LOCKS_SECRET=x` is a configuration that boots, works, looks
     * set to anyone reading the environment, and is brute-forceable offline.
     * Thirty-two is comfortably under what any reasonable encoding of 32 random
     * bytes produces, and far above what a placeholder does.
     */
    private const MINIMUM_SECRET_BYTES = 32;

    public static function for(string $ceremony, string $type, string $value): int
    {
        /*
         * Resolved rather than constructed, as AuthIdentifier::identity() does for
         * the same reason -- a static context cannot take constructor injection.
         * The canonicalizer is a singleton, and this class is the one place where
         * using an unconfigured second instance would be a correctness bug rather
         * than a style one: the whole argument for a fixed bucket count is that the
         * bucket canonicalizes IDENTICALLY to what the supersession predicate
         * compares. Should the canonicalizer ever take configuration, a private
         * instance here would quietly disagree with the configured one the
         * ceremonies use, and two spellings sharing one supersession scope would
         * take different mutexes -- the under-bucketing this design rules out,
         * arriving through a seam nothing observes.
         */
        $canonicalizer = app(IdentifierCanonicalizer::class);

        /*
         * The ceremony is part of the hashed message rather than a column:
         * recovery and verification for one address are different issuances and
         * need not block each other, and one bucket space serves both.
         */
        $digest = hash_hmac('sha256', self::message(
            $ceremony,
            $canonicalizer->canonicalize($type),
            $canonicalizer->canonicalize($value),
        ), self::secret(), true);

        /*
         * The first four bytes, composed by hand rather than through unpack():
         * unpack() hands back mixed and would need an unreachable failure branch
         * to narrow. 2^32 is a multiple of COUNT, so reducing modulo COUNT is
         * unbiased and every seeded bucket is reachable -- a derivation taking a
         * slice narrower than COUNT seeds correctly and leaves most of the table
         * permanently unreachable.
         */
        $high = (ord($digest[0]) << 24)
            | (ord($digest[1]) << 16)
            | (ord($digest[2]) << 8)
            | ord($digest[3]);

        return $high % self::COUNT;
    }

    /**
     * The dedicated keying secret, or a refusal naming what an operator must set.
     *
     * Public because boot validates it: a mutex secret is not something a host
     * gets to be lazily wrong about, since every issuance needs it and there is
     * no configuration in which the package works and this is absent. The
     * alternative to refusing is worse than a crash -- an empty secret is
     * accepted by hash_hmac, and every installation would then share one publicly
     * derivable mapping.
     */
    public static function secret(): string
    {
        $configured = Config::get(self::SECRET_KEY);

        if (! is_string($configured) || $configured === '') {
            throw new RuntimeException(
                'Vouch requires a dedicated issuance-mutex secret: set '
                . self::SECRET_KEY . ' (VOUCH_ISSUANCE_LOCKS_SECRET). '
                . 'The package ships no default, because a shared one would give '
                . 'every installation the same derivable bucket mapping.',
            );
        }

        if (strlen($configured) < self::MINIMUM_SECRET_BYTES) {
            throw new RuntimeException(sprintf(
                'The issuance-mutex secret is too short: %s '
                . '(VOUCH_ISSUANCE_LOCKS_SECRET) needs at least %d bytes.',
                self::SECRET_KEY,
                self::MINIMUM_SECRET_BYTES,
            ));
        }

        return $configured;
    }

    /**
     * Fill in every bucket row that is not there, and change nothing that is.
     *
     * Here rather than in a migration, for the reason IdentifierEqualityUpgrade
     * records: two migrations seed these rows -- the creating one, and the upgrade
     * for a host that already ran it -- and each naming the count itself is how
     * two callers come to disagree about it. A migration file is also recompiled
     * on every migrate, and the suite runs hundreds of them.
     *
     * Re-entrant rather than merely recorded-once. `migrate` skips a migration it
     * has already run, so an unconditional insert looks idempotent right up to the
     * one time the statements execute again -- and with the primary key present it
     * throws there rather than doubling the table.
     *
     * The connection is the caller's rather than the default binding, so this
     * behaves the same on a host migrating a non-default connection.
     */
    public static function seed(ConnectionInterface $connection): void
    {
        if ($connection->table(self::TABLE)->count() === self::COUNT) {
            return;
        }

        $rows = [];

        for ($bucket = 0; $bucket < self::COUNT; $bucket++) {
            $rows[] = ['bucket' => $bucket];
        }

        foreach (array_chunk($rows, self::SEED_CHUNK) as $chunk) {
            $connection->table(self::TABLE)->insertOrIgnore($chunk);
        }
    }

    /**
     * The hashed message, with structural segment boundaries.
     *
     * Count and byte-length prefixes rather than a delimiter, matching how the
     * package derives every other segmented key: a caller cannot make
     * ["a", "\0b"] collide with ["a\0", "b"], so two distinct scopes cannot be
     * spelled into one bucket deliberately.
     */
    private static function message(string ...$segments): string
    {
        $message = self::DOMAIN . "\0" . pack('N', count($segments));

        foreach ($segments as $segment) {
            $message .= "\0" . pack('N', strlen($segment)) . $segment;
        }

        return $message;
    }
}
