<?php

declare(strict_types=1);

namespace Fissible\Vouch\Verification;

use Fissible\Vouch\Identifiers\IdentifierGuard;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;

final readonly class IdentifierVerificationRequest
{
    public function __construct(
        public string $type,
        public string $submittedIdentifier,
        public ?string $tenantId,
        public ?string $clientIp,
    ) {
        // Both halves, in the constructor, for the reasons
        // CredentialRecoveryRequest records: the type is the other half of the
        // unique index and reaches a column of its own, and a guard at one call
        // site leaves every other caller unguarded.
        IdentifierGuard::assertWellFormed($type);
        IdentifierGuard::assertWellFormed($submittedIdentifier);
    }

    /**
     * The same request with identity decided by Vouch rather than by whichever
     * collation the host's database carries.
     *
     * Returned rather than applied in the constructor: what arrives here is
     * what someone typed, and the ceremony decides that two spellings are one
     * address -- not a value object reaching into the container.
     */
    public function canonicalized(IdentifierCanonicalizer $identifiers): self
    {
        return new self(
            type: $identifiers->canonicalize($this->type),
            submittedIdentifier: $identifiers->canonicalize($this->submittedIdentifier),
            tenantId: $this->tenantId,
            clientIp: $this->clientIp,
        );
    }
}
