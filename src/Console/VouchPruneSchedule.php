<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Closure;
use RuntimeException;

/** Preserves vouch:prune's three-way exit contract through Laravel scheduling. */
final class VouchPruneSchedule
{
    /** @param Closure(string): void $deliveryHealthAlert */
    public static function after(
        int $status,
        string $output,
        Closure $deliveryHealthAlert,
    ): void {
        if ($status === CommandExit::DeliveryHealth->value) {
            $deliveryHealthAlert(trim($output));

            return;
        }

        if ($status === CommandExit::Success->value) {
            return;
        }

        throw new RuntimeException(sprintf(
            'vouch:prune failed with status %d.',
            $status,
        ));
    }
}
