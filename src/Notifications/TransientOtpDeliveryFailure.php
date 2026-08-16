<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use RuntimeException;

/**
 * Redacted retry signal.
 *
 * Provider exceptions may contain a destination or even echo request payload.
 * Queue logs and failed-job storage persist the thrown exception, so the
 * original must not cross this boundary.
 */
final class TransientOtpDeliveryFailure extends RuntimeException
{
}
