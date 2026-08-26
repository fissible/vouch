<?php

declare(strict_types=1);

namespace Fissible\Vouch\Verification;

final readonly class IdentifierVerificationRequest
{
    public function __construct(
        public string $type,
        public string $submittedIdentifier,
        public ?string $tenantId,
        public ?string $clientIp,
    ) {}
}
