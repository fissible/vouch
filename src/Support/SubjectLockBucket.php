<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Fissible\Vouch\Tokens\SubjectKey;

/**
 * #17. The mutex for one token subject.
 *
 * 2.4 Task 5a gave each subject a permanent anchor row, which kept a record
 * naming every subject ever issued a token, surviving the host deleting the
 * user. A bucket keeps the serialization and discards the identity.
 *
 * Provider and id are separate length-prefixed segments, so the same id under
 * two providers, or "7" and "07", are different scopes.
 */
final class SubjectLockBucket
{
    public const TABLE = 'auth_subject_locks';

    public const DOMAIN = 'token.subject';

    /** @return non-empty-list<int> */
    public static function buckets(SubjectKey $subject): array
    {
        return LockBucket::all(self::DOMAIN, $subject->provider, $subject->id);
    }
}
