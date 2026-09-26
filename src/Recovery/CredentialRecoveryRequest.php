<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Throttle\IdentifierCanonicalizer;

final readonly class CredentialRecoveryRequest
{
    public function __construct(
        public string $type,
        public string $submittedIdentifier,
        public ?int $tenantId,
        public string $clientIp,
    ) {}

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
