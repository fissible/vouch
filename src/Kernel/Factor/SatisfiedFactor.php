<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Factor;

use DateTimeImmutable;

/**
 * One factor, actually satisfied, with everything policy needs to judge it.
 *
 * `isMultiFactor` is true for a user-verified passkey: possession of the
 * authenticator plus a biometric or PIN, which NIST treats as AAL2 on its own.
 * `authenticatorId` distinguishes two credentials living on the same device,
 * which are not independent authenticators.
 *
 * Credential identity is checked here because token proofs, session proofs,
 * and attempt evidence all carry this value. A check at each writer would
 * leave the next writer unprotected; rebuilding stored evidence must refuse
 * the same invalid identities as constructing fresh evidence.
 */
final readonly class SatisfiedFactor
{
    public function __construct(
        public string $factorId,
        public string $credentialId,
        public FactorKind $kind,
        public FactorStrength $strength,
        public bool $isMultiFactor,
        public bool $userVerified,
        public bool $phishingResistant,
        public ?string $authenticatorId,
        public DateTimeImmutable $satisfiedAt,
    ) {
        CredentialId::validate($credentialId);
    }
}
