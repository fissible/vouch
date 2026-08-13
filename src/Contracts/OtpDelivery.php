<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use DateTimeImmutable;
use Fissible\Vouch\Models\AuthIdentifier;

/**
 * Delivers a one-time code to a verified identifier.
 *
 * A seam rather than an implementation: vouch depends on neither a mail
 * transport nor an SMS gateway, and the host decides both. The plaintext code
 * exists only in this call — it is never stored, never logged, and never
 * returned to the caller.
 */
interface OtpDelivery
{
    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void;
}
