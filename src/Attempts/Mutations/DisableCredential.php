<?php

declare(strict_types=1);

namespace Fissible\Vouch\Attempts\Mutations;

/**
 * Retire a credential permanently — a spent recovery code, in practice.
 */
final readonly class DisableCredential implements SingleUseMutation
{
    public function __construct(
        public int $credentialId,
    ) {}

    public function target(): string
    {
        return 'credential:' . $this->credentialId;
    }
}
