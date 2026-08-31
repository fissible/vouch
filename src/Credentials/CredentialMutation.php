<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

use Fissible\Vouch\Tokens\CredentialLockManager;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Illuminate\Database\Connection;
use Illuminate\Support\Facades\Log;
use Throwable;

/** Serializes credential writes with assurance invalidation. */
final readonly class CredentialMutation
{
    public function __construct(
        private Connection $connection,
        private CredentialLockManager $locks,
        private TokenIssuerRegistry $issuers,
        private TokenAssuranceRecord $records,
    ) {}

    /** @param callable $write */
    public function additive(SubjectKey $subject, callable $write): CredentialMutationResult
    {
        return $this->mutate($subject, [], false, $write);
    }

    /**
     * A LIST of credential ids, matching CredentialLockManager's own contract.
     * Accepting array<string> here and widening the lock manager to suit would
     * relax the protocol to fit a caller; callers build these from factors and
     * already have lists.
     *
     * @param list<string> $credentialIds
     */
    public function revoking(SubjectKey $subject, array $credentialIds, callable $write): CredentialMutationResult
    {
        return $this->mutate($subject, CredentialLockManager::canonicalCredentialIds($credentialIds), false, $write);
    }

    /** @param callable $write */
    public function subjectWide(SubjectKey $subject, callable $write): CredentialMutationResult
    {
        return $this->mutate($subject, [], true, $write);
    }

    /**
     * Typed as a LIST because that is what it receives: canonicalCredentialIds()
     * returns one and subjectWide() passes []. Widening CredentialLockManager to
     * accept array<string> instead would weaken the protocol's own contract to
     * silence a call site, which is the wrong end to fix.
     *
     * @param list<string> $credentialIds
     */
    private function mutate(SubjectKey $subject, array $credentialIds, bool $subjectWide, callable $write): CredentialMutationResult
    {
        /*
         * Vouch's invalidation must commit before a driver's revoke() can run.
         * Registering the driver work with afterCommit() enforces that at every
         * nesting level: a top-level mutation runs it before transaction()
         * returns, while a nested mutation defers it to its caller's outermost
         * commit. A rollback runs neither the driver work nor its failures.
         *
         * The latter updates the returned result only when the caller commits.
         * Until then driverRevocationsComplete is false, so an empty failure
         * list cannot be mistaken for successful driver cleanup.
         * additive() registers no callbacks and continues to join freely.
         */
        $result = new CredentialMutationResult;

        $mutate = function () use ($subject, $credentialIds, $subjectWide, $write, $result): array {
            $this->locks->acquire($this->connection, $subject, $credentialIds);

            /*
             * Replacement writers can only build their explicit id list before
             * acquiring the subject lock. Capture the authoritative credential
             * state after that lock instead: anything this write then disables
             * must withdraw the proofs that cite it, even if it was absent from
             * the caller's stale list.
             *
             * A stale additive declaration has a second failure mode. It can
             * revive a row that became disabled after classification, while
             * replacing its secret. That is a password-like credential
             * replacement, and must be no weaker than subjectWide(). The floor
             * is deliberately keyed on the secret as well as disabled_at: a
             * secretless OTP reactivation leaves the proof true and remains
             * additive.
             *
             * subjectWide() already withdraws every human proof, so neither
             * comparison can affect its result and need not be read.
             */
            $beforeWrite = $subjectWide ? [] : $this->credentialStates($subject);
            $write($this->connection);

            $credentialIds = CredentialLockManager::canonicalCredentialIds([
                ...$credentialIds,
                ...$this->credentialIdsDisabledSince($beforeWrite),
            ]);
            $subjectWide = $subjectWide || $this->revivedWithDifferentSecret($beforeWrite, $subject);

            $revoked = $this->records->forgetHumanForCredentialMutation(
                $subject, $credentialIds, $subjectWide, $this->connection,
            );

            foreach ($revoked as $row) {
                $this->connection->afterCommit(function () use ($row, $result): void {
                    foreach ($this->issuers->issuers() as $issuer) {
                        if ($issuer->issuerKey() !== $row->issuer_key) {
                            continue;
                        }

                        try {
                            $issuer->revoke($row->token_key);
                        } catch (Throwable $failure) {
                            $driverFailure = new CredentialDriverFailure(
                                $row->issuer_key, $row->token_key, $failure->getMessage(),
                            );
                            $result->recordDriverFailure($driverFailure);

                            // Callers commonly do not retain the result. Record
                            // this here, at the shared post-commit boundary, so
                            // a failed driver revoke remains discoverable even
                            // while the token gate is intentionally observing.
                            try {
                                Log::warning('Vouch driver token revocation failed.', [
                                    'issuer_key' => $driverFailure->issuerKey,
                                    'token_key' => $driverFailure->tokenKey,
                                ]);
                            } catch (Throwable) {
                                // Reporting must not turn best-effort cleanup
                                // into a failure of the caller's commit.
                            }
                        }

                        break;
                    }
                });
            }

            if ($revoked !== []) {
                // Registered last, this runs only after every per-token callback
                // at the outermost commit.
                $this->connection->afterCommit($result->markDriverRevocationsComplete(...));
            } else {
                $result->markDriverRevocationsComplete();
            }

            return $revoked;
        };

        /** @var list<object{issuer_key: string, token_key: string}> $revoked */
        $revoked = $this->connection->transactionLevel() === 0
            ? $this->connection->transaction($mutate)
            : $mutate();

        $result->revoked = count($revoked);

        return $result;
    }

    /** @return array<string, CredentialState> */
    private function credentialStates(SubjectKey $subject): array
    {
        $states = [];
        foreach ($this->connection->table('auth_credentials')
            ->select(['id', 'secret', 'disabled_at'])
            ->where('user_id', $subject->id)
            ->orderBy('id')
            ->get() as $credential) {
            $id = $this->credentialId($credential->id);
            if (! is_string($credential->secret) && $credential->secret !== null) {
                throw new \LogicException('Credential storage returned an invalid secret snapshot.');
            }

            $states[$id] = new CredentialState(
                $id,
                $credential->secret,
                $credential->disabled_at !== null,
            );
        }

        return $states;
    }

    /**
     * @param array<string, CredentialState> $beforeWrite
     * @return list<string>
     */
    private function credentialIdsDisabledSince(array $beforeWrite): array
    {
        $activeCredentialIds = [];
        foreach ($beforeWrite as $id => $credential) {
            if (! $credential->disabled) {
                $activeCredentialIds[] = $id;
            }
        }

        if ($activeCredentialIds === []) {
            return [];
        }

        return array_values(array_map(
            $this->credentialId(...),
            $this->connection->table('auth_credentials')
                ->whereIn('id', $activeCredentialIds)
                ->whereNotNull('disabled_at')
                ->orderBy('id')
                ->pluck('id')
                ->all(),
        ));
    }

    /**
     * @param array<string, CredentialState> $beforeWrite
     */
    private function revivedWithDifferentSecret(array $beforeWrite, SubjectKey $subject): bool
    {
        foreach ($this->credentialStates($subject) as $id => $afterWrite) {
            $before = $beforeWrite[$id] ?? null;

            if ($before !== null
                && $before->disabled
                && ! $afterWrite->disabled
                && $before->secret !== $afterWrite->secret) {
                return true;
            }
        }

        return false;
    }

    private function credentialId(mixed $id): string
    {
        if (! is_int($id) && ! is_string($id)) {
            throw new \LogicException('Credential storage returned an invalid credential identity.');
        }

        return (string) $id;
    }
}
