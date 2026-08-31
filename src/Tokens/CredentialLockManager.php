<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use Illuminate\Database\ConnectionInterface;

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
     * Credential identities are opaque strings: for example, `9` and `09`
     * name different credentials. Every path that locks credentials must use
     * canonicalCredentialIds(), rather than database primary-key order.
     */
    public function acquire(ConnectionInterface $connection, SubjectKey $subject, array $credentialIds): void
    {
        $this->connection = $connection;
        $credentialIds = self::canonicalCredentialIds($credentialIds);

        $this->lockSubject($subject);

        foreach ($credentialIds as $credentialId) {
            $this->lockCredential($credentialId);
        }
    }

    /**
     * The protocol's single credential-lock order.
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
        $this->connection()->table('auth_sessions')
            ->where('user_id', $subject->id)
            ->lockForUpdate()
            ->first();
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
