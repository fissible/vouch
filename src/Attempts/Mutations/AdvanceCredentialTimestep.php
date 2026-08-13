<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * Move a TOTP credential's replay watermark forward.
 *
 * Shares the "credential:N" target namespace with DisableCredential
 * deliberately: applying both to one credential in a single transition is a
 * conflict worth refusing, not a combination worth supporting.
 */
final readonly class AdvanceCredentialTimestep implements SingleUseMutation
{
    public function __construct(
        public int $credentialId,
        public int $timestep,
    ) {}

    public function target(): string
    {
        return 'credential:' . $this->credentialId;
    }
}
