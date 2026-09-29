<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Support\Facades\Config;
use InvalidArgumentException;

/**
 * #55/#82. The configured attempt window, or a refusal naming what to set.
 *
 * One predicate with two callers, and that is the whole reason this class exists.
 * Provider boot refuses an unusable window, and exempts vouch:doctor so the one
 * command whose job is to REPORT a misconfiguration is not stopped by one -- which
 * only holds if the report asks the same question boot does.
 *
 * The other three doctor-exempt checks already share their predicate with boot:
 * IssuanceLockBucket::secret(), AssuranceRequirements::assertDeclared(), and a
 * one-line instanceof. This one was a compound condition written inline in boot
 * (`! is_int($ttl) || $ttl < 1`), so a report re-implementing it could drift.
 * Measured: adding `|| $ttl > 86400` to boot's copy left the whole suite green
 * while VOUCH_ATTEMPT_TTL=90000 refused boot for every command except the doctor,
 * which then called that host healthy -- #82 verbatim, reintroduced, and no test
 * that counts exemptions or reads the provider's source would see it.
 *
 * Both halves of the condition are load-bearing and neither implies the other.
 * `vouch.attempts.ttl_seconds` ships as `(int) env('VOUCH_ATTEMPT_TTL', 600)`, so
 * a blank environment variable arrives as zero -- non-positive but correctly
 * typed; and a published config whose cast has been edited away hands over the
 * STRING "600" -- positive by any numeric reading, but rejected downstream by
 * AuthFlow's config()->integer(), which is where every login would fail instead.
 *
 * Deliberately not cached: the clock-source tests change configuration and forget
 * only AuthFlow, so a value memoized here would answer from a stale environment.
 * DatabaseTime keeps its own guard for callers that receive a TTL from somewhere
 * other than configuration.
 *
 * @internal
 */
final class AttemptWindow
{
    /** Named once, because boot validates it and the doctor row is titled with it. */
    public const KEY = 'vouch.attempts.ttl_seconds';

    private function __construct() {}

    /** @throws InvalidArgumentException when the configured window cannot describe one */
    public static function seconds(): int
    {
        $configured = Config::get(self::KEY);

        if (! is_int($configured) || $configured < 1) {
            throw ConfigurationError::positiveInteger($configured, self::KEY);
        }

        return $configured;
    }
}
