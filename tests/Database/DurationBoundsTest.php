<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;

uses(RefreshDatabase::class);

/*
 * #81. The top end of a configured duration.
 *
 * #55 closed the bottom and the type domain of `vouch.attempts.ttl_seconds`: boot refuses
 * anything that is not a positive integer. A positive integer too LARGE for the engine's
 * interval arithmetic still boots cleanly and then fails every login.
 *
 * Measured with VOUCH_ATTEMPT_TTL=999999999999 -- a plausible fat-fingered value:
 *
 *   SQLite      datetime('now', printf('%+d seconds', ?))      returns NULL
 *   MySQL       DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND) returns NULL
 *   PostgreSQL  succeeds to year 33715; SQLSTATE[22008] near PHP_INT_MAX
 *
 * On two of three engines that is a per-request 500 today, and the defensive failure --
 * "The database returned an invalid deadline value" -- names neither the setting nor the
 * value, so the diagnostic #55 added for the bottom end is missing here.
 *
 * WHAT THE BOUND IS. Not a policy number. A duration is usable only if the instants it
 * describes are representable, so the limit is the arithmetic's own, taken at the
 * intersection of the engines the package supports because one configuration has to work on
 * all three. Measured, in seconds from today:
 *
 *   engine      now + N            now - N
 *   sqlite      251,611,250,923    212,657,809,876
 *   mysql       251,611,250,923     63,958,269,076
 *   pgsql       299,999,999,999+   212,657,853,077
 *
 * Both directions matter: a throttle window is compared as "at or before now minus N", so a
 * duration is used backwards as well as forwards. The binding constraint is therefore MySQL
 * going back, and it is about two thousand years -- far outside any legitimate authentication
 * window and comfortably inside a fat-fingered one.
 *
 * WHICH SETTINGS ARE ACTUALLY OPEN. The issue reasons that "every sibling TTL in the package
 * accepts any positive integer, so a cap on this one alone would be stricter than its siblings for
 * no stated reason". Measured, that premise does not hold: six of the nine refuse 999999999999
 * already, through rules that are better than an arithmetic bound because they are semantic --
 *
 *   window_seconds                  retention must be at least window + 3600
 *   global/ip/tenant.backoff_seconds  observe mode requires these to be null
 *   identifier.backoff_cap_seconds  must be at most window_seconds
 *   identifier.lock_duration_seconds must not exceed 3600; longer locks are a different decision
 *   challenge.attempts              the 10^-4 online-guess target
 *
 * Three are open, and they are the whole of #81:
 *
 *   vouch.attempts.ttl_seconds
 *   vouch.throttle.retention_seconds
 *   vouch.throttle.identifier.initial_backoff_seconds
 *
 * So the bound is not repo-wide after all; it is the arithmetic's floor under the three settings
 * that have no semantic ceiling, plus the clock guard for callers handed a duration from somewhere
 * other than configuration.
 *
 * WHY NOT THE SHARED INTEGER READER. `ThrottleConfiguration`'s positive() serves durations AND
 * `vouch.throttle.challenge.attempts`, a count with no clock domain. Bounding the reader would
 * reach that too, and the last control here is what notices: the count's refusal must still name
 * the guess-probability rule, which is the rule that should own it.
 */

/**
 * Durations spanning ordinary, enormous-but-representable, and past every engine's range.
 *
 * @return array<string, array{int}>
 */
function durationSweep(): array
{
    return [
        'ten minutes' => [600],
        'a day' => [86400],
        'a year' => [31557600],
        'a century' => [3155760000],
        'a millennium' => [31557600000],
        'past what MySQL can go back' => [63958269077],
        'past what SQLite and MySQL can go forward' => [251611250924],
        'the fat-fingered value from the issue' => [999999999999],
        'the largest integer there is' => [PHP_INT_MAX],
    ];
}

/** Re-run provider boot with one setting replaced, forgetting the package's singletons first. */
function bootWithDuration(string $key, mixed $value): void
{
    Config::set($key, $value);

    /*
     * Every Vouch-namespaced singleton, rather than a named few: the provider resolves its
     * validating services eagerly, so a leftover instance would answer from the configuration
     * this test just replaced, and naming services would pin WHICH object carries the check.
     */
    foreach (array_keys(app()->getBindings()) as $abstract) {
        if (is_string($abstract) && str_starts_with($abstract, 'Fissible\\Vouch\\')) {
            app()->forgetInstance($abstract);
        }
    }

    (new VouchServiceProvider(app()))->boot();
}

/* ---- the clock guard, which is the property rather than the number ---- */

it('either refuses a duration as configuration or returns a real deadline for it', function (int $seconds): void {
    /*
     * The property #81 is actually about, and it is engine-agnostic: no duration may reach the
     * database and come back as a surprise. Today the large ones do -- they produce
     * RuntimeException("The database returned an invalid deadline value"), which tells an
     * operator nothing about which setting to change.
     *
     * Asserted as a disjunction on purpose. Pinning the exact boundary here would restate the
     * implementation's own arithmetic and would pass for any bound it chose, including a wrong
     * one; this passes only if every outcome is either a usable instant or a configuration
     * error, which is the thing that is broken.
     */
    try {
        $deadline = app(DatabaseTime::class)->deadline($seconds);

        expect($deadline->format('Y'))->toBeGreaterThan('1000');

        return;
    } catch (InvalidArgumentException $e) {
        // A configuration error has to say what was wrong with it.
        expect($e->getMessage())->toContain((string) $seconds);

        return;
    }
})->with(durationSweep());

it('names the value when it refuses one the arithmetic cannot represent', function (): void {
    /*
     * The diagnostic half, stated separately from the disjunction above so that an
     * implementation refusing with an empty message cannot satisfy it. 999999999999 is the
     * issue's own measured value.
     */
    expect(fn () => app(DatabaseTime::class)->deadline(999999999999))
        ->toThrow(InvalidArgumentException::class, '999999999999');
});

it('keeps refusing a duration below one second', function (): void {
    // #55's guard, unchanged: the top end is being added to it, not replacing it.
    expect(fn () => app(DatabaseTime::class)->deadline(0))
        ->toThrow(InvalidArgumentException::class);
});

it('still produces a usable deadline for an ordinary duration', function (): void {
    /*
     * The positive control, and it has to be a real round trip: a guard that refused everything
     * would satisfy every refusal above.
     */
    $before = app(DatabaseTime::class)->current();
    $deadline = app(DatabaseTime::class)->deadline(600);

    expect($deadline->getTimestamp() - $before->getTimestamp())->toBeGreaterThanOrEqual(595);
    expect($deadline->getTimestamp() - $before->getTimestamp())->toBeLessThanOrEqual(605);
});

/* ---- boot, for every setting that describes a duration ---------------- */

it('fails boot on a duration setting too large for the arithmetic', function (string $key): void {
    /*
     * Per setting, because the issue's point is that bounding one of them alone is arbitrary:
     * every sibling goes through the same positive-integer reader and the same clock, so either
     * they are all bounded or the bound is a special case for whichever setting someone
     * fat-fingered first.
     *
     * The setting must name itself. An operator reading "must be at most ..." without the key
     * has several candidates in config/vouch.php.
     */
    expect(fn () => bootWithDuration($key, 999999999999))
        ->toThrow(InvalidArgumentException::class, $key);
})->with([
    'vouch.attempts.ttl_seconds',
    'vouch.throttle.retention_seconds',
    'vouch.throttle.identifier.initial_backoff_seconds',
]);

it('leaves the siblings that already have a semantic ceiling to their own rule', function (string $key, string $owner): void {
    /*
     * The other six, asserted as still refusing for THEIR reason rather than a new one. A
     * duration bound that fired first would take these over, replacing a message that says what
     * the real constraint is -- "retention must be at least window + 3600", "longer locks require
     * a different decision" -- with one that says only that a number is too big.
     *
     * This is also the control that keeps the new bound off the shared reader: if it were there,
     * every message below would change.
     */
    expect(fn () => bootWithDuration($key, 999999999999))
        ->toThrow(InvalidArgumentException::class, $owner);
})->with([
    ['vouch.throttle.window_seconds', 'vouch.throttle.retention_seconds'],
    ['vouch.throttle.global.backoff_seconds', 'observe mode'],
    ['vouch.throttle.ip.backoff_seconds', 'observe mode'],
    ['vouch.throttle.tenant.backoff_seconds', 'observe mode'],
    ['vouch.throttle.identifier.backoff_cap_seconds', 'must be less than or equal to'],
    ['vouch.throttle.identifier.lock_duration_seconds', 'must not exceed 3600'],
]);

it('reports an unusable duration through vouch:doctor rather than refusing to run it', function (): void {
    /*
     * #82's invariant, and the reason this bound must live in the predicate boot and the doctor
     * SHARE rather than inline in boot. AttemptWindow's docblock records the measurement:
     * adding `|| $ttl > 86400` to boot's own copy left the whole suite green while
     * VOUCH_ATTEMPT_TTL=90000 refused boot for every command except the doctor, which then
     * called that host healthy -- #82 verbatim, reintroduced.
     *
     * So the command whose job is to report a misconfiguration must still run, and must report
     * THIS one.
     */
    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:doctor'];

        // Must not throw: an exception here fails the test by itself.
        bootWithDuration('vouch.attempts.ttl_seconds', 999999999999);

        $rows = doctorRows();

        expect($rows)->toHaveKey('vouch.attempts.ttl_seconds');
        expect($rows['vouch.attempts.ttl_seconds']['ok'] ?? true)->toBeFalse();

        /*
         * The control, in the same test so the two cannot drift: the identical value under
         * ordinary argv is still refused. Without it, deleting the bound entirely would satisfy
         * the exemption above.
         */
        $_SERVER['argv'] = ['artisan', 'about'];

        expect(fn () => bootWithDuration('vouch.attempts.ttl_seconds', 999999999999))
            ->toThrow(InvalidArgumentException::class);
    } finally {
        if ($original === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $original;
        }
    }
});

/* ---- and what must NOT be bounded ------------------------------------- */

it('leaves a count to the rule that should own it', function (): void {
    /*
     * `vouch.throttle.challenge.attempts` goes through the same positive-integer reader as every
     * duration above, and it is already bounded -- by the 10^-4 online-guess target, which is the
     * right owner for it. An implementation that bounded the READER would refuse it first and the
     * message would change, which is what this notices.
     *
     * There is no value that is both past the arithmetic bound and acceptable to the probability
     * rule, so this cannot be written as "a large count still boots".
     */
    expect(fn () => bootWithDuration('vouch.throttle.challenge.attempts', 999999999999))
        ->toThrow(InvalidArgumentException::class, 'online-guess target');
});

it('accepts every duration the package itself ships', function (): void {
    /*
     * The cheapest way to pass a boot check is a default that satisfies it, and the cheapest way
     * to fail a fresh install is one that does not. Read with the environment unset, which is the
     * only way to ask what a new host gets.
     */
    $published = publishedVouchConfig();

    expect($published)->toHaveKey('attempts');

    bootWithDuration('vouch.attempts.ttl_seconds', is_array($published['attempts'] ?? null)
        ? ($published['attempts']['ttl_seconds'] ?? null)
        : null);
});
