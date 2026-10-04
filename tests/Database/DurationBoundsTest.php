<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * #81. The top end of a configured duration.
 *
 * #55 closed the bottom and the type domain of `vouch.attempts.ttl_seconds`: boot refuses anything
 * that is not a positive integer. A positive integer too large still boots cleanly and then fails
 * every login, with the defensive error naming neither the setting nor the value -- so the
 * diagnostic #55 added for the bottom end is missing at the top.
 *
 * WHAT THE BOUND IS. Not a policy number: a duration is usable only if the instants it describes
 * can be represented, so the limit belongs to the engines. The relevant range is now the DATE
 * COLUMN's, since the 2038 conversion moved every one of them to a type that reaches year 9999, and
 * MySQL's DATETIME is the narrowest the package supports -- documented as 1000-01-01 00:00:00 to
 * 9999-12-31 23:59:59. A duration is therefore usable only while `now + N` and `now - N` both fall
 * inside it.
 *
 * Both directions, because a throttle window is compared as "at or before now minus N" and the
 * retention cutoff is a past instant. From today the backward direction binds, at roughly a
 * thousand years.
 *
 * Measured rather than assumed, resolving AND storing each candidate, which is the step an earlier
 * attempt at this issue skipped: it bounded the arithmetic alone and missed that the destination
 * column was the real constraint.
 *
 *   engine      resolves and stores, forward   backward
 *   sqlite      251,611,216,257                212,657,844,542
 *   mysql       251,611,216,257                 63,926,681,342
 *   pgsql       299,999,999,999+               212,657,887,743
 *
 * MySQL accepted dates behind its own documented floor, back to year 1. The bound uses the
 * DOCUMENTED range anyway: a security package should not rest on an engine being more permissive
 * than its contract.
 *
 * WHICH SETTINGS THIS REACHES, measured by booting each with 999999999999. Eight boot today and
 * are what #81 is about:
 *
 *   vouch.attempts.ttl_seconds                          vouch.otp.ttl_seconds
 *   vouch.recovery_grace.ttl_seconds                    vouch.verification.ttl_seconds
 *   vouch.recovery.ttl_seconds                          vouch.throttle.retention_seconds
 *   vouch.sessions.revocation_retention_days            vouch.throttle.identifier.initial_backoff_seconds
 *
 * Three are already refused by rules of their own, which are better than an arithmetic bound
 * because they are semantic -- retention must exceed the window by an hour, the backoff cap must be
 * at most the window, a lock must not exceed 3600 seconds -- and they keep that ownership below.
 *
 * And two must NOT be bounded by this, which is the control for the whole change:
 * `vouch.enrollment.lock_wait_seconds` is a database lock timeout that never becomes a stored date,
 * and `vouch.throttle.ip.ipv4_observe_at` is a count. A bound that reached the shared
 * positive-integer reader would take both.
 */

/**
 * Durations spanning ordinary, large-but-representable, and past what any engine can hold.
 *
 * @return array<string, array{int}>
 */
function durationSweep(): array
{
    return [
        'ten minutes' => [600],
        'a day' => [86400],
        'a year' => [31557600],
        // A century, which the 2038 conversion is what made storable at all.
        'a century' => [3155760000],
        'past the documented floor going back' => [63926681343],
        'past what any engine resolves forward' => [251611216258],
        'the fat-fingered value from the issue' => [999999999999],
        'the largest integer there is' => [PHP_INT_MAX],
    ];
}

/**
 * Every configured duration that becomes a stored instant and has no earlier rule of its own.
 *
 * @return array<string, array{string}>
 */
function unboundedDurationSettings(): array
{
    return [
        'vouch.attempts.ttl_seconds' => ['vouch.attempts.ttl_seconds'],
        'vouch.recovery_grace.ttl_seconds' => ['vouch.recovery_grace.ttl_seconds'],
        'vouch.recovery.ttl_seconds' => ['vouch.recovery.ttl_seconds'],
        'vouch.otp.ttl_seconds' => ['vouch.otp.ttl_seconds'],
        'vouch.verification.ttl_seconds' => ['vouch.verification.ttl_seconds'],
        'vouch.sessions.revocation_retention_days' => ['vouch.sessions.revocation_retention_days'],
        'vouch.throttle.retention_seconds' => ['vouch.throttle.retention_seconds'],
        'vouch.throttle.identifier.initial_backoff_seconds' => ['vouch.throttle.identifier.initial_backoff_seconds'],
    ];
}

/** Re-run provider boot with one setting replaced, forgetting the package's singletons first. */
function bootWithDuration(string $key, mixed $value): void
{
    Config::set($key, $value);

    /*
     * Every Vouch-namespaced singleton rather than a named few: the provider resolves its
     * validating services eagerly, so a leftover instance would answer from the configuration this
     * test just replaced -- and naming services would pin WHICH object carries the check.
     */
    foreach (array_keys(app()->getBindings()) as $abstract) {
        if (is_string($abstract) && str_starts_with($abstract, 'Fissible\\Vouch\\')) {
            app()->forgetInstance($abstract);
        }
    }

    (new VouchServiceProvider(app()))->boot();
}

/* ---- the clock guard, asserted as a property --------------------------- */

it('either refuses a duration as configuration or returns a deadline that stores', function (int $seconds): void {
    /*
     * The property, and the store is half of it. An earlier form of this test asserted only that
     * the returned value parsed, and a century-long duration satisfied that and then failed to
     * store with error 1292 -- which was the whole defect.
     *
     * A disjunction on purpose: pinning the exact boundary here would restate the implementation's
     * own arithmetic and would pass for any bound it chose, including a wrong one. What cannot
     * happen is a duration reaching the database and coming back as a surprise.
     */
    try {
        $deadline = app(DatabaseTime::class)->deadline($seconds);
    } catch (InvalidArgumentException $e) {
        // A configuration error has to say what was wrong with it.
        expect($e->getMessage())->toContain((string) $seconds);

        return;
    }

    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => str_repeat('a', 64),
        'locked_until' => $deadline,
        'created_at' => app(DatabaseTime::class)->current(),
        'updated_at' => app(DatabaseTime::class)->current(),
    ]);

    $stored = DB::table('auth_throttle_locks')->where('subject_digest', str_repeat('a', 64))->value('locked_until');

    expect(is_string($stored) ? substr($stored, 0, 19) : '')->toBe($deadline->format('Y-m-d H:i:s'));
})->with(durationSweep());

it('names the value when it refuses one that cannot be represented', function (): void {
    // Stated separately from the disjunction so an implementation refusing with an empty message
    // cannot satisfy it. 999999999999 is the issue's own measured value.
    expect(fn () => app(DatabaseTime::class)->deadline(999999999999))
        ->toThrow(InvalidArgumentException::class, '999999999999');
});

it('keeps refusing a duration below one second', function (): void {
    // #55's guard. The top end is being added to it, not replacing it.
    expect(fn () => app(DatabaseTime::class)->deadline(0))
        ->toThrow(InvalidArgumentException::class);
});

it('resolves and stores a century, which is what the 2038 conversion bought', function (): void {
    /*
     * The positive control with teeth. Before the date columns moved off TIMESTAMP this resolved
     * and then failed to store, so a guard calibrated to that ceiling would have refused it -- and
     * refusing a century is the wrong answer now that the column can hold one.
     */
    $deadline = app(DatabaseTime::class)->deadline(3155760000);

    expect((int) $deadline->format('Y'))->toBeGreaterThan(2100);

    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => str_repeat('b', 64),
        'locked_until' => $deadline,
        'created_at' => app(DatabaseTime::class)->current(),
        'updated_at' => app(DatabaseTime::class)->current(),
    ]);

    expect(DB::table('auth_throttle_locks')->where('subject_digest', str_repeat('b', 64))->count())->toBe(1);
});

/* ---- boot, for every duration that has no earlier rule ----------------- */

it('fails boot on a duration setting too large to represent', function (string $key): void {
    /*
     * Per setting, because the issue's point is that bounding one of them alone is arbitrary: every
     * sibling reads through the same clock, so either they are all bounded or the bound is a
     * special case for whichever setting somebody fat-fingered first.
     *
     * The setting must name itself. "Must be at most ..." without the key leaves an operator
     * several candidates in config/vouch.php, and the value must appear too -- the blank-environment
     * case #55 covers is exactly where the value an operator SET is not the value that arrived.
     */
    expect(fn () => bootWithDuration($key, 999999999999))
        ->toThrow(InvalidArgumentException::class, $key);
})->with(unboundedDurationSettings());

it('names the offending value as well as the setting', function (): void {
    try {
        bootWithDuration('vouch.attempts.ttl_seconds', 999999999999);
    } catch (InvalidArgumentException $e) {
        expect($e->getMessage())->toContain('999999999999');

        return;
    }

    throw new RuntimeException('Boot accepted an attempt ttl that cannot be represented.');
});

it('reports an unusable duration through vouch:doctor rather than refusing to run it', function (): void {
    /*
     * #82's invariant, and the reason this bound must live in the predicate boot and the doctor
     * SHARE. AttemptWindow's docblock records the measurement: adding `|| $ttl > 86400` to boot's
     * own copy left the whole suite green while VOUCH_ATTEMPT_TTL=90000 refused boot for every
     * command except the doctor, which then called that host healthy -- #82 verbatim, reintroduced.
     */
    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:doctor'];

        // Must not throw: an exception here fails the test by itself.
        bootWithDuration('vouch.attempts.ttl_seconds', 999999999999);

        expect(doctorStatus('vouch.attempts.ttl_seconds'))->not->toBe('pass');

        /*
         * The control, in the same test so the two cannot drift: the identical value under ordinary
         * argv is still refused. Without it, deleting the bound would satisfy the exemption above.
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

/* ---- and what must NOT be bounded -------------------------------------- */

it('leaves alone a setting that never becomes a stored instant', function (string $key): void {
    /*
     * The control for the whole change. Both of these read through the same positive-integer reader
     * as the durations above, so an implementation that bounded the READER would take them too --
     * and neither describes a date. A lock wait is a database timeout; an observe threshold is a
     * count. Refusing an absurd value for either is a different decision that nobody has made.
     */
    bootWithDuration($key, 999999999999);

    expect(true)->toBeTrue();
})->with([
    'vouch.enrollment.lock_wait_seconds' => ['vouch.enrollment.lock_wait_seconds'],
    'vouch.throttle.ip.ipv4_observe_at' => ['vouch.throttle.ip.ipv4_observe_at'],
]);

it('leaves a semantically bounded sibling to its own rule', function (string $key, string $owner): void {
    /*
     * Three settings already refuse an absurd value through a rule that says what the real
     * constraint is. A duration bound firing first would replace "retention must be at least window
     * + 3600" or "longer locks require a different decision" with a message that says only that a
     * number is too big, and the operator would learn less.
     */
    expect(fn () => bootWithDuration($key, 999999999999))
        ->toThrow(InvalidArgumentException::class, $owner);
})->with([
    ['vouch.throttle.window_seconds', 'vouch.throttle.retention_seconds'],
    ['vouch.throttle.identifier.backoff_cap_seconds', 'must be less than or equal to'],
    ['vouch.throttle.identifier.lock_duration_seconds', 'must not exceed 3600'],
]);

it('leaves a count to the rule that should own it', function (): void {
    /*
     * `vouch.throttle.challenge.attempts` is already bounded, by the 10^-4 online-guess target,
     * which is the right owner. An implementation that bounded the shared reader would refuse it
     * first and the message would change -- which is what this notices. There is no value both past
     * the duration bound and acceptable to the probability rule, so this cannot be written as "a
     * large count still boots".
     */
    expect(fn () => bootWithDuration('vouch.throttle.challenge.attempts', 999999999999))
        ->toThrow(InvalidArgumentException::class, 'online-guess target');
});

it('accepts every duration the package itself ships', function (): void {
    /*
     * The cheapest way to pass a boot check is a default that satisfies it, and the cheapest way to
     * fail a fresh install is one that does not. Read with the environment unset, which is the only
     * way to ask what a new host gets.
     */
    $published = publishedVouchConfig();

    expect($published)->toHaveKey('attempts');

    foreach (array_keys(unboundedDurationSettings()) as $key) {
        $path = explode('.', $key);
        array_shift($path);
        $value = $published;

        foreach ($path as $segment) {
            $value = is_array($value) ? ($value[$segment] ?? null) : null;
        }

        expect($value)->toBeInt();

        bootWithDuration($key, $value);
    }
});
