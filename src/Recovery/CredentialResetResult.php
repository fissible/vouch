<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Fissible\Vouch\Credentials\CredentialDriverFailureIdentity;

/**
 * Password-reset outcome with identities of failed driver revokes from both passes.
 *
 * CredentialChangeFailed means revocation committed but the credential write
 * rolled back. Driver failures describe cleanup at the issuer independently
 * of that outcome, and contain no internal exception diagnostics.
 */
final readonly class CredentialResetResult
{
    /** @param list<CredentialDriverFailureIdentity> $driverFailures */
    public function __construct(
        public CredentialRecoveryOutcome $outcome,
        public array $driverFailures = [],
    ) {}
}
