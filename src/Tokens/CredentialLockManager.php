<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use Fissible\Vouch\Kernel\Factor\CredentialId;
use Illuminate\Database\ConnectionInterface;
use Fissible\Vouch\Support\DatabaseRowLock;
use Fissible\Vouch\Support\SubjectLockBucket;

/**
 * Serializes human-token issuance with credential mutation.
 *
 * The protected acquisition steps are deliberately overridable: the ordering is
 * a protocol contract, and callers can observe it without depending on a
 * database engine's lock syntax.
 */
class CredentialLockManager
{
    private ?ConnectionInterface $connection = null;

    /**
     * @param list<string> $credentialIds
     *
     * Credential identities are positive signed bigints carried as canonical
     * decimal strings. The schema treats `9` and `09` as the same row, so the
     * latter must be refused before a query can coerce it. Validate the whole
     * list before taking even the subject lock: a refusal must not leave locks
     * held for an otherwise valid prefix of the request.
     *
     * Every locking path uses canonicalCredentialIds() for deterministic string
     * order, rather than database primary-key order; it does not define identity.
     */
    public function acquire(ConnectionInterface $connection, SubjectKey $subject, array $credentialIds): void
    {
        foreach ($credentialIds as $credentialId) {
            CredentialId::validate($credentialId);
        }

        $this->connection = $connection;
        $credentialIds = self::canonicalCredentialIds($credentialIds);

        $this->lockSubject($subject);

        foreach ($credentialIds as $credentialId) {
            $this->lockCredential($credentialId);
        }
    }

    /**
     * The protocol's single deterministic order over decimal strings: `10`
     * precedes `9`. Deduplication and SORT_STRING establish lock order only;
     * acquire() checks the domain before any lock is taken.
     *
     * @param list<string> $credentialIds
     * @return list<string>
     */
    public static function canonicalCredentialIds(array $credentialIds): array
    {
        $credentialIds = array_values(array_unique($credentialIds, SORT_STRING));
        sort($credentialIds, SORT_STRING);

        return $credentialIds;
    }

    /**
     * #17. Lock the subject's buckets, ascending, before any credential.
     *
     * A subject with no session still serializes, because every bucket is
     * seeded before anyone asks. Unrelated subjects sharing a bucket serialize
     * too, which is latency and never shared state. No path locks two subjects
     * in one transaction, so bucket sharing adds no deadlock cycle.
     *
     * On SQLite row locks are no-ops and the database write lock is the mutex.
     * The 5a anchor took it with a leading insert, so the buckets are claimed
     * with a no-op UPDATE there: a read alone would let a second writer in.
     */
    protected function lockSubject(SubjectKey $subject): void
    {
        $connection = $this->connection();
        $buckets = SubjectLockBucket::buckets($subject);

        if ($connection->getDriverName() === 'sqlite') {
            $connection->table(SubjectLockBucket::TABLE)
                ->whereIn('bucket', $buckets)
                ->update(['bucket' => new \Illuminate\Database\Query\Expression('bucket')]);
        }

        (new DatabaseRowLock($connection))->lockBuckets(SubjectLockBucket::TABLE, $buckets);
    }

    protected function lockCredential(string $credentialId): void
    {
        $this->connection()->table('auth_credentials')
            ->where('id', $credentialId)
            ->lockForUpdate()
            ->first();
    }

    private function connection(): ConnectionInterface
    {
        if ($this->connection === null) {
            throw new \LogicException('Credential locks require an active connection.');
        }

        return $this->connection;
    }
}
