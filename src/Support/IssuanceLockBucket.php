<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Database\ConnectionInterface;

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
 * #16 moved the keyed derivation into LockBucket and the secret into
 * LockBucketSecret, unchanged for this domain, so the mapping an install already
 * uses does not move. Rotation no longer needs a coordinated deploy: see
 * LockBucketSecret.
 */
final class IssuanceLockBucket
{
    public const COUNT = LockBucket::COUNT;

    /** The table the buckets are rows of. */
    public const TABLE = 'auth_proof_issuance_locks';

    /** #46's domain label, unchanged so the mapping does not move. */
    public const DOMAIN = 'issuance.mutex';

    /** The bucket under the CURRENT secret. Locks take buckets(). */
    public static function for(string $ceremony, string $type, string $value): int
    {
        return LockBucket::under(LockBucketSecret::current(), self::DOMAIN, ...self::segments($ceremony, $type, $value));
    }

    /**
     * Every bucket an issuance lock must hold, ascending: two during a rotation
     * overlap, otherwise one.
     *
     * @return non-empty-list<int>
     */
    public static function buckets(string $ceremony, string $type, string $value): array
    {
        return LockBucket::all(self::DOMAIN, ...self::segments($ceremony, $type, $value));
    }

    public static function seed(ConnectionInterface $connection): void
    {
        LockBucket::seed($connection, self::TABLE);
    }

    /** @return list<string> */
    private static function segments(string $ceremony, string $type, string $value): array
    {
        /*
         * Resolved rather than constructed: the bucket must canonicalize
         * IDENTICALLY to what the supersession predicate compares, so a private,
         * unconfigured canonicalizer here would be a correctness bug. The
         * ceremony is a segment rather than a column, so recovery and
         * verification for one address do not block each other.
         */
        $canonicalizer = app(IdentifierCanonicalizer::class);

        return [
            $ceremony,
            $canonicalizer->canonicalize($type),
            $canonicalizer->canonicalize($value),
        ];
    }
}
