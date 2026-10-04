<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
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
 * DIRECTION FOLLOWS THE CONSUMER, which is the part that is easy to get wrong in the safe-looking
 * direction. A deadline and an issuance TTL only ever describe a FUTURE instant; a retention cutoff
 * only ever a past one; a throttle window is compared as "at or before now minus N" and also dates
 * rows forward. Validating both directions everywhere looks stricter and is simply wrong: measured,
 * now + 40,000,000,000 seconds resolves and stores on all three engines as year 3294, and refusing
 * an OTP TTL of that size because its unused BACKWARD instant lands in year 0759 would impose a
 * restriction nothing in the package needs. So forward-validated settings get the forward range,
 * retention gets the backward one, and only the throttle window needs both.
 *
 * WHICH SETTINGS THIS REACHES, measured by booting each with 999999999999. Seven boot today and
 * are what #81 is about:
 *
 *   forward  vouch.attempts.ttl_seconds            vouch.otp.ttl_seconds
 *            vouch.recovery_grace.ttl_seconds      vouch.verification.ttl_seconds
 *            vouch.recovery.ttl_seconds
 *   backward vouch.sessions.revocation_retention_days   (DAYS, not seconds)
 *            vouch.throttle.retention_seconds
 *
 * Retention produces a comparison cutoff rather than a stored timestamp, which is why its direction
 * is backward and why it is still in scope: an unrepresentable cutoff makes the comparison fail, not
 * the write.
 *
 * `vouch.throttle.identifier.initial_backoff_seconds` is deliberately NOT here, though it boots.
 * Measured: its consumer clamps it to the backoff cap, so 999999999999 produces an effective first
 * delay of 60 seconds and can never reach the clock. Refusing the raw value would be a new
 * configuration policy rather than a representability bound, and nobody has decided that.
 *
 * Three settings already refuse through rules of their own -- retention must exceed the window by an
 * hour, the cap must be at most the window, a lock must not exceed 3600 seconds -- and they keep
 * that ownership below. Two must NOT be bounded by this: `vouch.enrollment.lock_wait_seconds` is a
 * database lock timeout that reaches connection settings and never becomes a date, and
 * `vouch.throttle.ip.ipv4_observe_at` is a count. The IPv4 one is the real shared-reader control:
 * traced, the enrollment wait does not read through ThrottleConfiguration::positive() at all and its
 * consumer is lazy, so its booting proves less than it looks.
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
 * Settings whose instant is only ever in the FUTURE.
 *
 * @return array<string, array{string}>
 */
function forwardDurationSettings(): array
{
    return [
        'vouch.attempts.ttl_seconds' => ['vouch.attempts.ttl_seconds'],
        'vouch.recovery_grace.ttl_seconds' => ['vouch.recovery_grace.ttl_seconds'],
        'vouch.recovery.ttl_seconds' => ['vouch.recovery.ttl_seconds'],
        'vouch.otp.ttl_seconds' => ['vouch.otp.ttl_seconds'],
        'vouch.verification.ttl_seconds' => ['vouch.verification.ttl_seconds'],
    ];
}

/**
 * Settings whose instant is only ever in the PAST, with a value that is out of range in that
 * setting's own unit and comfortably in range if the unit is ignored.
 *
 * Measured, and this is what discriminates a missing unit conversion: 500000 retention DAYS reaches
 * year 0657, while 500000 seconds is six days. An implementation treating days as seconds passed
 * every case that used one enormous common value for both.
 *
 * @return array<string, array{string, int}>
 */
function backwardDurationSettings(): array
{
    return [
        'retention days' => ['vouch.sessions.revocation_retention_days', 500000],
        'retention seconds' => ['vouch.throttle.retention_seconds', 40000000000],
    ];
}

/**
 * Run $body with every named environment variable unset.
 *
 * The suite's withEnvironmentVariable() clears one at a time, so this nests it rather than
 * reimplementing the save-and-restore it already does correctly.
 *
 * @param  list<string>  $names
 */
function withoutDurationEnvironment(array $names, callable $body): mixed
{
    if ($names === []) {
        return $body();
    }

    $name = array_shift($names);

    return withEnvironmentVariable($name, null, static fn (): mixed => withoutDurationEnvironment($names, $body));
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
    $before = app(DatabaseTime::class)->current();

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

    /*
     * And it has to be the duration that was ASKED for. Measured: an implementation clamping every
     * accepted duration to a hundred years satisfied the storage comparison completely, because the
     * value stored was compared only against the value returned. PostgreSQL showed the same shape
     * from the other side -- a raw year 33715 parsed as 2005 and stored happily.
     */
    expect(abs(($deadline->getTimestamp() - $before->getTimestamp()) - $seconds))->toBeLessThan(5);
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

it('accepts a duration whose instant is inside the documented range, and refuses one past it', function (): void {
    /*
     * The endpoints, mandatory rather than left to the disjunction. Measured: an implementation
     * capping every duration at a hundred years satisfied the whole sweep, because the sweep only
     * requires each value to be refused OR usable and a clamp refuses nothing.
     *
     * Derived from the DOCUMENTED range -- MySQL DATETIME ends 9999-12-31 -- rather than from the
     * implementation's arithmetic: the targets are absolute years and the durations are whatever
     * reaches them from now.
     */
    $now = app(DatabaseTime::class)->current();
    $inside = (new DateTimeImmutable('9000-01-01 00:00:00', new DateTimeZone('UTC')))->getTimestamp() - $now->getTimestamp();
    $past = (new DateTimeImmutable('9999-12-31 23:59:59', new DateTimeZone('UTC')))->getTimestamp() - $now->getTimestamp() + 86400;

    $deadline = app(DatabaseTime::class)->deadline($inside);

    expect((int) $deadline->format('Y'))->toBe(9000);

    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => str_repeat('c', 64),
        'locked_until' => $deadline,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    expect(DB::table('auth_throttle_locks')->where('subject_digest', str_repeat('c', 64))->count())->toBe(1);

    expect(fn () => app(DatabaseTime::class)->deadline($past))
        ->toThrow(InvalidArgumentException::class);
});

/* ---- boot, for every duration that has no earlier rule ----------------- */

it('fails boot on a forward duration too large to represent', function (string $key): void {
    /*
     * Per setting, because bounding one alone is arbitrary: every sibling reads through the same
     * clock. The setting must name itself -- "must be at most ..." without the key leaves an
     * operator several candidates in config/vouch.php -- and so must the value, since the
     * blank-environment case #55 covers is exactly where the value an operator SET is not the one
     * that arrived.
     *
     * Measured: a counter-implementation that omitted the value from seven of the eight messages
     * passed every case that asserted only the key.
     */
    try {
        bootWithDuration($key, 999999999999);
    } catch (InvalidArgumentException $e) {
        expect($e->getMessage())->toContain($key);
        expect($e->getMessage())->toContain('999999999999');

        return;
    }

    throw new RuntimeException('Boot accepted ' . $key . ' at a value that cannot be represented.');
})->with(forwardDurationSettings());

it('fails boot on a backward duration too large to represent, in its own unit', function (string $key, int $value): void {
    // The unit is the point here; see backwardDurationSettings().
    try {
        bootWithDuration($key, $value);
    } catch (InvalidArgumentException $e) {
        expect($e->getMessage())->toContain($key);
        expect($e->getMessage())->toContain((string) $value);

        return;
    }

    throw new RuntimeException('Boot accepted ' . $key . ' at a value whose cutoff cannot be represented.');
})->with(backwardDurationSettings());

it('accepts a clamped backoff at a raw value that could never be represented', function (): void {
    /*
     * The exclusion, asserted rather than only explained. Measured: this setting's consumer clamps
     * it to the backoff cap, so 999999999999 produces an effective first delay of 60 seconds and
     * never reaches the clock -- refusing the raw value would be a new configuration policy rather
     * than a representability bound.
     *
     * Without this case, an implementation that bounded this setting too would satisfy every other
     * assertion in the file, and the exclusion would be a comment with nothing behind it.
     */
    bootWithDuration('vouch.throttle.identifier.initial_backoff_seconds', 999999999999);

    /*
     * The configuration carries the raw value, so it was not rejected. The clamp itself lives in
     * the consumer rather than here, which is why this asserts acceptance and the comment above
     * carries the measurement instead.
     */
    expect(app(ThrottleConfiguration::class)->initialBackoffSeconds)->toBe(999999999999);
});

it('accepts a forward duration that reaches far ahead but stays representable', function (string $key): void {
    /*
     * Direction follows the consumer, and this is the case that proves it. Measured: now plus
     * 40,000,000,000 seconds resolves and stores on all three engines as year 3294, while the same
     * number BACKWARD lands in year 0759. An implementation validating both directions for every
     * setting would refuse this, which nothing in the package requires.
     *
     * Over every forward setting, not just one: with OTP alone, applying both-direction validation
     * to the other four would still satisfy their refusal and shipped-default cases.
     */
    bootWithDuration($key, 40000000000);

    expect(true)->toBeTrue();
})->with(forwardDurationSettings());

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

        /*
         * The row has to EXIST and report the problem. Measured: deleting the doctor's TTL row
         * entirely left doctorStatus() returning null, which satisfied "not pass" -- so the
         * command would call a broken host healthy by saying nothing about it, which is #82.
         */
        expect(doctorStatus('vouch.attempts.ttl_seconds'))->toBe('missing');

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
     * fail a fresh install is one that does not.
     *
     * Read with the environment CLEARED, which the previous form claimed and did not do: measured,
     * publishedVouchConfig() under VOUCH_OTP_TTL=12345 returns 12345, so a host's environment was
     * being mistaken for what the package ships.
     */
    $settings = array_merge(
        array_map(static fn (array $row): string => $row[0], array_values(forwardDurationSettings())),
        array_map(static fn (array $row): string => $row[0], array_values(backwardDurationSettings())),
    );

    $variables = [
        'VOUCH_ATTEMPT_TTL', 'VOUCH_RECOVERY_GRACE_TTL', 'VOUCH_RECOVERY_TTL', 'VOUCH_OTP_TTL',
        'VOUCH_VERIFICATION_TTL', 'VOUCH_REVOCATION_RETENTION_DAYS', 'VOUCH_THROTTLE_RETENTION_SECONDS',
    ];

    $published = withoutDurationEnvironment($variables, static fn (): mixed => publishedVouchConfig());

    expect($published)->toBeArray();

    foreach ($settings as $key) {
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
