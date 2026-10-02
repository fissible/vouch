<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use Fissible\Vouch\Kernel\Factor\CredentialId;
use Illuminate\Database\ConnectionInterface;
use Fissible\Vouch\Support\DatabaseRowLock;

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

    protected function lockSubject(SubjectKey $subject): void
    {
        (new DatabaseRowLock($this->connection()))->ensureAndLock(
            'auth_subject_locks',
            ['subject_key' => $subject->toString()],
            ['subject_key' => $subject->toString()],
        );
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
