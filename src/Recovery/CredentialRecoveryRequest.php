<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Identifiers\IdentifierGuard;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;

final readonly class CredentialRecoveryRequest
{
    public function __construct(
        public string $type,
        public string $submittedIdentifier,
        public ?int $tenantId,
        public string $clientIp,
    ) {
        /*
         * In the constructor rather than in the ceremony, and on BOTH halves.
         * Nothing downstream may hold an instance of this carrying bytes an
         * identifier cannot be made of: canonicalized() would hand invalid UTF-8
         * to Symfony, the throttle key canonicalizes it before any of this is
         * looked up, and a guard installed at one call site leaves every other
         * caller -- including a host's own -- unguarded.
         *
         * Length is NOT checked here. It is measured on the canonical form
         * against each column's own width, which is a decision the model makes on
         * the write path; this object holds what somebody typed.
         */
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
