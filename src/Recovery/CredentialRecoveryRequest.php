<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

final readonly class CredentialRecoveryRequest
{
    public function __construct(
        public string $type,
        public string $submittedIdentifier,
        public ?int $tenantId,
        public string $clientIp,
    ) {}
}
