<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Database\ConnectionInterface;

/**
 * #16. Which mutex row a scope takes, for every bucketed lock in the package.
 *
 * A mutex does not need to know what it protects. Hashing the scope into a
 * fixed, seeded set of rows keeps the serialization and discards the identity,
 * so the table never grows and retains nothing (#46).
 *
 * Keyed, because an unkeyed mapping lets a caller work out which bucket a scope
 * lands in and aim traffic at it, turning false sharing into a denial of
 * service. Domains share one secret and are separated by the label inside the
 * hashed message. Deriving a key per domain instead would have moved every
 * existing issuance bucket on upgrade.
 *
 * The cost is false sharing: two unrelated scopes in one bucket serialize for
 * one transaction. That is latency, never shared state.
 */
final class LockBucket
{
    /**
     * Rows each bucket table seeds, and the modulus of the derivation. With C
     * simultaneous distinct scopes an arriving one shares a bucket with
     * probability about (C-1)/4096. Changing it moves every scope's bucket.
     */
    public const COUNT = 4096;

    private const SEED_CHUNK = 512;

    /** The bucket for one scope under one secret. */
    public static function under(string $secret, string $domain, string ...$segments): int
    {
        // A variadic can receive named arguments; only position is meaningful.
        $digest = hash_hmac('sha256', self::message($domain, array_values($segments)), $secret, true);

        /*
         * The first four bytes, composed by hand rather than through unpack(),
         * which returns mixed. 2^32 is a multiple of COUNT, so the reduction is
         * unbiased and every seeded bucket is reachable.
         */
        $high = (ord($digest[0]) << 24)
            | (ord($digest[1]) << 16)
            | (ord($digest[2]) << 8)
            | ord($digest[3]);

        return $high % self::COUNT;
    }

    /**
     * Every bucket a lock on this scope must hold: one per configured secret,
     * deduplicated and ascending.
     *
     * Ascending is what keeps the rotation overlap deadlock-free. Two updated
     * processes acquire in the same order, and a process still on the old
     * configuration takes a single bucket and waits on nothing else here.
     *
     * @return non-empty-list<int>
     */
    public static function all(string $domain, string ...$segments): array
    {
        $buckets = array_values(array_unique(array_map(
            static fn (string $secret): int => self::under($secret, $domain, ...$segments),
            LockBucketSecret::all(),
        )));
        sort($buckets);

        return $buckets;
    }

    /**
     * Fill in every bucket row that is not there, and change nothing that is.
     *
     * Re-entrant, because more than one migration seeds a table and `migrate`
     * can execute the same statements again. The connection is the caller's, so
     * a host migrating a non-default connection seeds the right database.
     */
    public static function seed(ConnectionInterface $connection, string $table): void
    {
        if ($connection->table($table)->count() === self::COUNT) {
            return;
        }

        $rows = [];

        for ($bucket = 0; $bucket < self::COUNT; $bucket++) {
            $rows[] = ['bucket' => $bucket];
        }

        foreach (array_chunk($rows, self::SEED_CHUNK) as $chunk) {
            $connection->table($table)->insertOrIgnore($chunk);
        }
    }

    /**
     * Count and byte-length prefixes rather than a delimiter, so ["a", "\0b"]
     * cannot collide with ["a\0", "b"]. Byte-identical to #46's message for the
     * issuance domain.
     *
     * @param list<string> $segments
     */
    private static function message(string $domain, array $segments): string
    {
        $message = $domain . "\0" . pack('N', count($segments));

        foreach ($segments as $segment) {
            $message .= "\0" . pack('N', strlen($segment)) . $segment;
        }

        return $message;
    }
}
