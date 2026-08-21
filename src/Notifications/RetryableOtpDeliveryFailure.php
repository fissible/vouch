<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use RuntimeException;

/** The economics store was contended; no provider call was attempted. */
final class RetryableOtpDeliveryFailure extends RuntimeException
{
}
