<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

/** Identity-only channel, populated when deferred driver callbacks run. */
final class CredentialDriverFailureReport
{
    /** @var list<CredentialDriverFailureIdentity> */
    public array $driverFailures = [];

    public function record(string $issuerKey, string $tokenKey): void
    {
        $this->driverFailures = CredentialDriverFailureIdentity::merge(
            $this->driverFailures,
            [new CredentialDriverFailureIdentity($issuerKey, $tokenKey)],
        );
    }
}
