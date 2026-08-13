<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use DateTimeImmutable;
use Illuminate\Support\Carbon;
use Psr\Clock\ClockInterface;

/**
 * The application clock, as PSR-20.
 *
 * Backed by Carbon rather than `new DateTimeImmutable` so that Laravel's
 * `travelTo()` and `Carbon::setTestNow()` move it. TOTP verification is a
 * function of the current time, and a clock the test suite cannot move would
 * make every timestep assertion depend on when the suite happened to run.
 *
 * This lives outside `src/Kernel/`, so the kernel boundary scan does not apply
 * and Carbon is a legitimate dependency here.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return Carbon::now('UTC')->toDateTimeImmutable();
    }
}
