<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;

/**
 * Everything a driver needs to issue a challenge.
 *
 * The credential is optional because several valid flows do not know one at
 * challenge time: OTP is addressed via the attempt's identifier, recovery-code
 * verification selects the matching code only after input arrives, and passkey
 * assertion begins before the authenticator has chosen. Forcing drivers to
 * invent a credential to satisfy a signature would be a lie in the type system.
 *
 * Client IP and user agent travel here because auth_challenges binds them and
 * the attempt carries only bound_context, which is the session.
 */
final readonly class ChallengeRequest
{
    public function __construct(
        public AuthAttempt $attempt,
        public ?AuthCredential $credential = null,
        public ?string $clientIp = null,
        public ?string $clientUserAgent = null,
    ) {}
}
