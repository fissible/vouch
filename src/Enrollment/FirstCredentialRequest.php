<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

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
    ) {}
}
