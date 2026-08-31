<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Assurance\EvidenceRead;
use Fissible\Vouch\Assurance\MalformedEvidence;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Illuminate\Database\ConnectionInterface;

final readonly class TokenAssuranceRecord
{
    public function __construct(private ConnectionInterface $connection) {}

    /** @param list<SatisfiedFactor> $factors */
    public function store(string $issuerKey, string $tokenKey, SubjectKey $subject, ?string $tenantId, ActorKind $actor, array $factors, ?ConnectionInterface $connection = null): void
    {
        $this->assertIdentity($issuerKey, $tokenKey);

        if ($actor === ActorKind::Machine) {
            if ($factors !== []) {
                throw new MalformedEvidence('A machine token cannot carry human assurance factors.');
            }
            $evidence = null;
        } else {
            $evidence = new AssuranceEvidence($subject, $tenantId, $factors);
            $this->assertCredentialIds($evidence->factors);
        }

        $connection ??= $this->connection;
        $write = function () use ($connection, $issuerKey, $tokenKey, $subject, $tenantId, $actor, $evidence): void {
            $connection->table('auth_token_credentials')
                ->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();
            $connection->table('auth_token_assurances')
                ->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();

            $connection->table('auth_token_assurances')->insert([
                'issuer_key' => $issuerKey,
                'token_key' => $tokenKey,
                'subject_key' => $subject->render(),
                'tenant_id' => $tenantId,
                'actor_kind' => $actor->value,
                'acr' => $evidence?->derivedAcr(),
                'assurance_proof' => $evidence === null ? null : json_encode($evidence->toArray(), JSON_THROW_ON_ERROR),
                'weakest_satisfied_at' => $evidence?->weakestSatisfiedAt(),
                'created_at' => now(),
                'updated_at' => now(),
            ]);

            if ($evidence !== null) {
                $credentialIds = array_values(array_unique(array_map(static fn (SatisfiedFactor $factor): string => $factor->credentialId, $evidence->factors)));
                $connection->table('auth_token_credentials')->insert(array_map(
                    static fn (string $credentialId): array => [
                        'issuer_key' => $issuerKey, 'token_key' => $tokenKey, 'credential_id' => $credentialId,
                    ],
                    $credentialIds,
                ));
            }
        };

        if ($connection->transactionLevel() < 1) {
            $connection->transaction($write);

            return;
        }

        $write();
    }

    public function read(ResolvedToken $token): EvidenceRead
    {
        // This order is the refusal contract: later checks must not relabel an
        // unusable token as missing, machine, malformed, or subject-mismatched.
        if (! $token->usable) {
            return new EvidenceRead(null, AssuranceReason::TokenUnusable);
        }
        $row = $this->connection->table('auth_token_assurances')
            ->where('issuer_key', $token->issuerKey)->where('token_key', $token->tokenKey)->first();
        if ($row === null) {
            return new EvidenceRead(null, AssuranceReason::NoAssuranceRecord);
        }
        try {
            $actor = ActorKind::from($row->actor_kind);
        } catch (\ValueError) {
            return new EvidenceRead(null, AssuranceReason::ProofMalformed);
        }
        if ($actor === ActorKind::Machine) {
            return new EvidenceRead(null, AssuranceReason::MachineActor);
        }
        if ($row->weakest_satisfied_at === null || ! is_string($row->assurance_proof)) {
            return new EvidenceRead(null, AssuranceReason::ProofMalformed);
        }
        try {
            $decoded = json_decode($row->assurance_proof, true, 512, JSON_THROW_ON_ERROR);
            if (! is_array($decoded)) {
                throw new MalformedEvidence('Evidence proof is malformed.');
            }
            $evidence = AssuranceEvidence::fromArray($decoded);
            $storedSubject = SubjectKey::fromString((string) $row->subject_key);
        } catch (\JsonException|MalformedEvidence|\InvalidArgumentException) {
            return new EvidenceRead(null, AssuranceReason::ProofMalformed);
        }
        if (! $storedSubject->equals($token->subject) || ! $evidence->subject->equals($token->subject)) {
            return new EvidenceRead(null, AssuranceReason::SubjectMismatch);
        }

        return new EvidenceRead($evidence, AssuranceReason::Sufficient);
    }

    public function forget(string $issuerKey, string $tokenKey, ?ConnectionInterface $connection = null): void
    {
        $this->assertIdentity($issuerKey, $tokenKey);
        $connection ??= $this->connection;
        $delete = static function () use ($connection, $issuerKey, $tokenKey): void {
            $connection->table('auth_token_credentials')->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();
            $connection->table('auth_token_assurances')->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();
        };

        if ($connection->transactionLevel() < 1) {
            $connection->transaction($delete);

            return;
        }

        $delete();
    }

    /**
     * Remove human assurance records affected by one credential mutation.
     *
     * @param list<string> $credentialIds
     * @return list<object{issuer_key: string, token_key: string}>
     */
    public function forgetHumanForCredentialMutation(SubjectKey $subject, array $credentialIds, bool $subjectWide, ?ConnectionInterface $connection = null): array
    {
        if (! $subjectWide && $credentialIds === []) {
            return [];
        }

        $connection ??= $this->connection;
        $query = $connection->table('auth_token_assurances as assurance')
            ->select('assurance.issuer_key', 'assurance.token_key')
            ->where('assurance.subject_key', $subject->render())
            ->where('assurance.actor_kind', ActorKind::Human->value);

        if (! $subjectWide) {
            $query->join('auth_token_credentials as credential', function ($join) use ($credentialIds): void {
                $join->on('credential.issuer_key', '=', 'assurance.issuer_key')
                    ->on('credential.token_key', '=', 'assurance.token_key')
                    ->whereIn('credential.credential_id', $credentialIds);
            });
        }

        /** @var list<object{issuer_key: string, token_key: string}> $rows */
        $rows = $query->distinct()->orderBy('assurance.issuer_key')->orderBy('assurance.token_key')->get()->all();
        foreach ($rows as $row) {
            $connection->table('auth_token_credentials')
                ->where('issuer_key', $row->issuer_key)->where('token_key', $row->token_key)->delete();
            $connection->table('auth_token_assurances')
                ->where('issuer_key', $row->issuer_key)->where('token_key', $row->token_key)->delete();
        }

        return $rows;
    }

    /** @return array<string, list<string>> */
    public function tokenKeysByIssuer(): array
    {
        $keysByIssuer = [];
        $rows = $this->connection->table('auth_token_assurances')
            ->orderBy('issuer_key')
            ->orderBy('token_key')
            ->get(['issuer_key', 'token_key']);

        foreach ($rows as $row) {
            if (! is_string($row->issuer_key) || ! is_string($row->token_key)) {
                throw new \LogicException('Token assurance storage returned an invalid identity.');
            }

            $keysByIssuer[$row->issuer_key][] = $row->token_key;
        }

        return $keysByIssuer;
    }

    /**
     * @param list<string> $tokenKeys
     */
    public function forgetMany(string $issuerKey, array $tokenKeys): int
    {
        foreach ($tokenKeys as $tokenKey) {
            $this->assertIdentity($issuerKey, $tokenKey);
        }

        if ($tokenKeys === []) {
            return 0;
        }

        return $this->connection->transaction(function () use ($issuerKey, $tokenKeys): int {
            $this->connection->table('auth_token_credentials')
                ->where('issuer_key', $issuerKey)
                ->whereIn('token_key', $tokenKeys)
                ->delete();

            return $this->connection->table('auth_token_assurances')
                ->where('issuer_key', $issuerKey)
                ->whereIn('token_key', $tokenKeys)
                ->delete();
        });
    }

    private function assertIdentity(string $issuerKey, string $tokenKey): void
    {
        if ($issuerKey === '' || $tokenKey === '') {
            throw new \InvalidArgumentException('Token assurance identity halves cannot be empty.');
        }
    }

    /** @param list<SatisfiedFactor> $factors */
    private function assertCredentialIds(array $factors): void
    {
        foreach ($factors as $factor) {
            if ($factor->credentialId === '') {
                throw new \InvalidArgumentException('Token assurance credential identities cannot be empty.');
            }
        }
    }
}
