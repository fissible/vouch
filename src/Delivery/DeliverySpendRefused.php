<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use RuntimeException;

/** Internal rollback sentinel for an atomic multi-scope reservation. */
final class DeliverySpendRefused extends RuntimeException
{
}
