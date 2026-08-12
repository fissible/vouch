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
    ) {}
}
