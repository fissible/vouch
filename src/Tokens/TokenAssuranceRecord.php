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
    public function store(string $issuerKey, string $tokenKey, SubjectKey $subject, ?string $tenantId, ActorKind $actor, array $factors): void
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

        $this->connection->transaction(function () use ($issuerKey, $tokenKey, $subject, $tenantId, $actor, $evidence): void {
            $this->connection->table('auth_token_credentials')
                ->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();
            $this->connection->table('auth_token_assurances')
                ->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();

            $this->connection->table('auth_token_assurances')->insert([
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
                $this->connection->table('auth_token_credentials')->insert(array_map(
                    static fn (string $credentialId): array => [
                        'issuer_key' => $issuerKey, 'token_key' => $tokenKey, 'credential_id' => $credentialId,
                    ],
                    $credentialIds,
                ));
            }
        });
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

    public function forget(string $issuerKey, string $tokenKey): void
    {
        $this->assertIdentity($issuerKey, $tokenKey);
        $this->connection->transaction(function () use ($issuerKey, $tokenKey): void {
            $this->connection->table('auth_token_credentials')->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();
            $this->connection->table('auth_token_assurances')->where('issuer_key', $issuerKey)->where('token_key', $tokenKey)->delete();
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
