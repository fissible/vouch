<?php

declare(strict_types=1);

namespace Fissible\Vouch\SelfService;

use Fissible\Vouch\Credentials\CredentialDriverFailureIdentity;
use Fissible\Vouch\Secrets\OneTimeSecret;

/**
 * What a credential change produced.
 *
 * Enrollment material cannot be retrieved later. Keep the driver's original
 * OneTimeSecret instances so the caller can reveal them once into the response,
 * without putting plaintext in a session, log, event, or queued payload.
 */
final readonly class SelfServiceResult
{
    /**
     * @param list<OneTimeSecret> $secrets
     * @param list<CredentialDriverFailureIdentity> $driverFailures
     */
    public function __construct(
        public SelfServiceOutcome $outcome,
        public array $secrets = [],
        public array $driverFailures = [],
    ) {}
}
