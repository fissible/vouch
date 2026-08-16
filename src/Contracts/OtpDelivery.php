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
 * exists only in an encrypted, TTL-bound outbox and in this worker call. It is
 * never stored unencrypted, logged, serialized into a queued job, or returned
 * to the authentication caller.
 */
interface OtpDelivery
{
    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void;
}
