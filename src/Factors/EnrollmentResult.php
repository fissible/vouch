<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Secrets\OneTimeSecret;

/**
 * What an enrollment produced.
 *
 * Not a bare AuthCredential: recovery-code enrollment creates ten of them, and
 * both TOTP and recovery produce plaintext that is shown once and never
 * retrievable again.
 *
 * Secrets are OneTimeSecret rather than strings because a provisioning URI and
 * a recovery code are bearer material. The flow layer in 2.3 must reveal each
 * exactly once, straight into the response, and put it in no session, log,
 * audit event, or queued payload.
 */
final readonly class EnrollmentResult
{
    /**
     * @param  list<AuthCredential>  $credentials
     * @param  list<OneTimeSecret>  $secrets
     */
    public function __construct(
        public array $credentials,
        public array $secrets = [],
    ) {}
}
