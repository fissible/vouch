<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

/** The credential fields that determine assurance invalidation. */
final readonly class CredentialState
{
    public function __construct(
        public string $id,
        public ?string $secret,
        public bool $disabled,
    ) {}
}
