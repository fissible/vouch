<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

use Fissible\Vouch\Identifiers\IdentifierGuard;

/** Input for the password bootstrap attached to a host-created user. */
final readonly class FirstCredentialRequest
{
    public function __construct(
        public int $userId,
        public string $identifierType,
        public string $identifierValue,
        public string $password,
        public ?string $tenantId,
        public ?string $clientIp,
    ) {
        // Enrollment is where an identifier is first claimed, so it is the
        // boundary that must not accept one nobody can spell back. Both halves,
        // for the reasons CredentialRecoveryRequest records.
        IdentifierGuard::assertWellFormed($identifierType);
        IdentifierGuard::assertWellFormed($identifierValue);
    }
}
