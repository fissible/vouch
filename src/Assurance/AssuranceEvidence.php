<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

use DateTimeImmutable;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tokens\SubjectKey;

final readonly class AssuranceEvidence
{
    /** @param list<SatisfiedFactor> $factors */
    public function __construct(public SubjectKey $subject, public ?string $tenantId, public array $factors)
    {
        if ($tenantId === '') {
            throw new MalformedEvidence('A tenant id cannot be empty.');
        }
        if ($factors === []) {
            throw new MalformedEvidence('Evidence must contain a non-empty factor list.');
        }
        if (AssuranceFacts::fromFactors($factors)->weakestSatisfiedAt === null) {
            throw new MalformedEvidence('Recovery-only evidence is not assurance evidence.');
        }
    }

    public function facts(): AssuranceFacts
    {
        return AssuranceFacts::fromFactors($this->factors);
    }

    public function weakestSatisfiedAt(): DateTimeImmutable
    {
        $weakest = AssuranceFacts::fromFactors($this->factors)->weakestSatisfiedAt;
        if (! $weakest instanceof DateTimeImmutable) {
            // The constructor rejects recovery-only evidence. Reaching this
            // branch means a future facts implementation broke that invariant.
            throw new \LogicException('Assurance evidence has no satisfied-at timestamp.');
        }

        return $weakest;
    }

    /** @return array{subject:string,tenant_id:?string,factors:list<array<string,mixed>>} */
    public function toArray(): array
    {
        return [
            'subject' => $this->subject->render(),
            'tenant_id' => $this->tenantId,
            'factors' => array_map(static fn (SatisfiedFactor $factor): array => [
                'factor_id' => $factor->factorId,
                'credential_id' => $factor->credentialId,
                'kind' => $factor->kind->value,
                'strength' => self::strengthKey($factor->strength),
                'is_multi_factor' => $factor->isMultiFactor,
                'user_verified' => $factor->userVerified,
                'phishing_resistant' => $factor->phishingResistant,
                'authenticator_id' => $factor->authenticatorId,
                'satisfied_at' => $factor->satisfiedAt->format('Y-m-d\\TH:i:s.uP'),
            ], $this->factors),
        ];
    }

    /** @param array<mixed> $value */
    public static function fromArray(array $value): self
    {
        if (array_is_list($value) || array_diff(array_keys($value), ['subject', 'tenant_id', 'factors']) !== []
            || ! array_key_exists('subject', $value) || ! array_key_exists('tenant_id', $value) || ! array_key_exists('factors', $value)
            || ! is_string($value['subject']) || (! is_string($value['tenant_id']) && $value['tenant_id'] !== null)
            || ! is_array($value['factors']) || array_is_list($value['factors']) === false) {
            throw new MalformedEvidence('Evidence envelope is malformed.');
        }
        try {
            $subject = SubjectKey::fromString($value['subject']);
        } catch (\InvalidArgumentException) {
            throw new MalformedEvidence('Evidence subject is malformed.');
        }

        $factors = array_map(static fn (mixed $factor): SatisfiedFactor => self::factor($factor), $value['factors']);

        return new self($subject, $value['tenant_id'], $factors);
    }

    private static function factor(mixed $value): SatisfiedFactor
    {
        $keys = ['factor_id', 'credential_id', 'kind', 'strength', 'is_multi_factor', 'user_verified', 'phishing_resistant', 'authenticator_id', 'satisfied_at'];
        if (! is_array($value) || array_is_list($value) || array_diff(array_keys($value), $keys) !== [] || array_diff($keys, array_keys($value)) !== []) {
            throw new MalformedEvidence('Evidence factor is malformed.');
        }
        foreach (['factor_id', 'credential_id'] as $key) {
            if (! is_string($value[$key]) || $value[$key] === '' || trim($value[$key]) !== $value[$key]) {
                throw new MalformedEvidence('Evidence factor key is malformed.');
            }
        }
        if (! is_string($value['kind']) || ! is_string($value['strength'])
            || ! is_bool($value['is_multi_factor']) || ! is_bool($value['user_verified']) || ! is_bool($value['phishing_resistant'])
            || (! is_string($value['authenticator_id']) && $value['authenticator_id'] !== null)
            || ! is_string($value['satisfied_at']) || $value['satisfied_at'] === ''
            || ! preg_match('/(?:Z|[+-]\d{2}:\d{2})$/', $value['satisfied_at'])) {
            throw new MalformedEvidence('Evidence factor fields are malformed.');
        }
        try {
            $kind = FactorKind::from($value['kind']);
            $strength = self::strength($value['strength']);
            $at = new DateTimeImmutable($value['satisfied_at']);
        } catch (\Exception|\ValueError) {
            throw new MalformedEvidence('Evidence factor fields are malformed.');
        }
        return new SatisfiedFactor($value['factor_id'], $value['credential_id'], $kind, $strength, $value['is_multi_factor'], $value['user_verified'], $value['phishing_resistant'], $value['authenticator_id'], $at);
    }

    private static function strength(string $value): FactorStrength
    {
        foreach (FactorStrength::cases() as $strength) {
            if (self::strengthKey($strength) === $value) {
                return $strength;
            }
        }

        throw new MalformedEvidence('Evidence strength is malformed.');
    }

    private static function strengthKey(FactorStrength $strength): string
    {
        return match ($strength) {
            FactorStrength::Recovery => 'recovery',
            FactorStrength::Knowledge => 'knowledge',
            FactorStrength::PossessionWeak => 'possession_weak',
            FactorStrength::Possession => 'possession',
            FactorStrength::PossessionStrong => 'possession_strong',
        };
    }
}
