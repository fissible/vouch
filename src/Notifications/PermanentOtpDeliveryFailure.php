<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use RuntimeException;

/** A provider refusal for which retrying the same delivery cannot succeed. */
final class PermanentOtpDeliveryFailure extends RuntimeException
{
}
