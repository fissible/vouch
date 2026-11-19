<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

/**
 * #16. The mutex for one IP's throttle window.
 *
 * The window row used to be its own mutex, so nothing could delete it and the
 * table grew with every client IP ever seen. With the mutex here, a window row
 * is ordinary state that pruning can reclaim under the bucket.
 */
final class IpThrottleLockBucket
{
    public const TABLE = 'auth_throttle_ip_locks';

    public const DOMAIN = 'throttle.ip';

    /** @return non-empty-list<int> */
    public static function buckets(string $dimension, string $ipDigest): array
    {
        return LockBucket::all(self::DOMAIN, $dimension, $ipDigest);
    }
}
