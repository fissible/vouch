<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

final readonly class CredentialDriverFailure
{
    public function __construct(public string $issuerKey, public string $tokenKey, public string $message) {}
}
