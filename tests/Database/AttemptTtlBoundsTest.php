<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Env;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * #55. When a TTL that cannot describe a window is rejected.
 *
 * `vouch.attempts.ttl_seconds` is `(int) env('VOUCH_ATTEMPT_TTL', 600)` and was
 * read with `config()->integer()`, which checks the type and nothing else. Zero, a
 * negative, and a set-but-blank environment variable -- which the cast turns into
 * zero -- all passed. The application then booted cleanly and AuthFlow resolved,
 * so nothing looked wrong until a request arrived and DatabaseTime::deadline()
 * refused it. Every login returned 500, with no deadline query and no attempt
 * insert.
 *
 * Throwing is right; the moment was wrong. A value that makes every login fail
 * belongs to the class of settings the provider already rejects at boot, beside
 * the throttle budget and the issuance-mutex secret -- configuration an operator
 * can still fix before traffic arrives, named in an error that says which setting
 * and what value.
 *
 * Two halves that must both hold, and they pull in opposite directions. Boot must
 * refuse the values that cannot work; and DatabaseTime::deadline() must KEEP its
 * own guard, because the boot check is where the error is useful, not a
 * replacement for the defensive one. An implementation that moved the guard rather
 * than adding to it would satisfy every refusal test here and leave the one place
 * that receives a TTL from somewhere other than configuration unprotected.
 *
 * Surfaced by #44, which put the attempt deadline on the database clock. Before
 * that a non-positive TTL produced attempts that were already expired: useless,
 * but quiet.
 */

/** A window no shipped default could produce, so a stale 600 cannot pass for it. */
const TTL_BOUNDS_VALID = 137;

/**
 * Re-run provider boot with the attempt TTL set to $value.
 *
 * ThrottleConfiguration is forgotten first because the provider resolves it
 * eagerly during boot, so the instance from the test application's own boot would
 * otherwise answer from the configuration this test just replaced.
 */
function bootWithAttemptTtl(mixed $value): void
{
    Config::set('vouch.attempts.ttl_seconds', $value);
    app()->forgetInstance(ThrottleConfiguration::class);
    app()->forgetInstance(AuthFlow::class);

    (new VouchServiceProvider(app()))->boot();
}

/* ---- the default the package ships must itself be acceptable ---------- */

it('ships an attempt ttl that its own boot check accepts', function (): void {
    /*
     * The positive control for every refusal below, and it is not rhetorical: the
     * cheapest way to make a boot check pass is a default that satisfies it, and
     * the cheapest way to make one fail on a fresh install is a default that does
     * not. Read from the package's config file with the environment unset, which
     * is the only way to ask what a fresh installation gets.
     */
    $shipped = withEnvironmentVariable('VOUCH_ATTEMPT_TTL', null, static function (): mixed {
        $published = publishedVouchConfig();
        $attempts = $published['attempts'] ?? null;

        return is_array($attempts) ? ($attempts['ttl_seconds'] ?? null) : null;
    });

    expect($shipped)->toBeInt();
    expect(is_int($shipped) && $shipped > 0)->toBeTrue(
        'config/vouch.php must ship a positive attempt ttl: a non-positive default fails every login',
    );

    // And the shipped value boots, rather than merely being positive in isolation.
    bootWithAttemptTtl($shipped);

    expect(app(ThrottleConfiguration::class))->toBeInstanceOf(ThrottleConfiguration::class);
});

/* ---- boot must refuse what cannot describe a window ------------------- */

it('fails boot on a non-positive attempt ttl', function (int $seconds): void {
    /*
     * Each value asserted to name itself. "Must be a positive integer" without the
     * offending value sends an operator to re-read a setting they already believe
     * is correct -- and the blank-environment case, where the value they SET is not
     * the value that arrived, is exactly where that matters.
     */
    try {
        bootWithAttemptTtl($seconds);

        throw new RuntimeException('Provider boot accepted an attempt ttl of ' . $seconds . '.');
    } catch (InvalidArgumentException $failure) {
        expect($failure->getMessage())->toContain('vouch.attempts.ttl_seconds');
        expect($failure->getMessage())->toContain((string) $seconds);
    }
})->with([
    'zero' => [0],
    'negative' => [-1],
    'a whole negative window' => [-600],
]);

it('resolves a blank attempt ttl environment variable to a value boot refuses', function (): void {
    /*
     * The case the issue singles out, and the one no Config::set() can reach: an
     * operator who writes `VOUCH_ATTEMPT_TTL=` in an .env has SET the variable, so
     * env() returns an empty string rather than the default, and the config file's
     * (int) cast turns it into zero. The two halves are asserted separately --
     * first that the environment really does arrive as zero, then that zero is
     * refused -- because a test that only checked the refusal would still pass if
     * the cast started yielding 600 and the blank case stopped existing.
     */
    $blank = withEnvironmentVariable('VOUCH_ATTEMPT_TTL', '', static function (): mixed {
        $published = publishedVouchConfig();
        $attempts = $published['attempts'] ?? null;

        return is_array($attempts) ? ($attempts['ttl_seconds'] ?? null) : null;
    });

    expect($blank)->toBe(0, 'a set-but-blank VOUCH_ATTEMPT_TTL must arrive as zero, not as the default');

    try {
        bootWithAttemptTtl($blank);

        throw new RuntimeException('Provider boot accepted the zero a blank VOUCH_ATTEMPT_TTL produces.');
    } catch (InvalidArgumentException $failure) {
        expect($failure->getMessage())->toContain('vouch.attempts.ttl_seconds');
    }
});

/* ---- and a valid window must still boot and still work ---------------- */

it('boots on a valid attempt ttl and dates an attempt by it', function (): void {
    /*
     * Criterion three, and the guard against a fix that refuses too much. Booting
     * is asserted first, then an attempt is actually begun: the reported symptom
     * was a 500 at the attempt insert, so "boot did not throw" alone would not
     * show that the path the operator cares about works.
     */
    bootWithAttemptTtl(TTL_BOUNDS_VALID);

    $before = app(DatabaseTime::class)->current();

    $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], str_repeat('t', 64)));

    expect($begun)->toBeInstanceOf(Continuing::class);

    $after = app(DatabaseTime::class)->current();

    $attempt = DB::table('auth_attempts')->orderByDesc('id')->first();
    $deadline = new DateTimeImmutable(stringValue(requiredRow($attempt)->expires_at));

    /*
     * Bracketed against the database clock either side of the write rather than
     * compared with a literal: PostgreSQL rounds CURRENT_TIMESTAMP(0) where
     * getTimestamp() truncates, so a fixed comparison fails on engine rounding
     * roughly half the time.
     */
    expect($deadline->getTimestamp())->toBeGreaterThanOrEqual($before->getTimestamp() + TTL_BOUNDS_VALID);
    expect($deadline->getTimestamp())->toBeLessThanOrEqual($after->getTimestamp() + TTL_BOUNDS_VALID);
});

/* ---- the defensive guard is not replaced by the boot one -------------- */

it('keeps the database deadline guard for callers that are not configuration', function (): void {
    /*
     * DatabaseTime::deadline() takes an int from whoever calls it, and configuration
     * is only one of those callers. Moving the guard to boot instead of adding to it
     * would satisfy every test above while leaving a computed or passed-through
     * window unchecked, which is the shape that put a non-positive value there in
     * the first place.
     */
    $time = app(DatabaseTime::class);

    expect(static fn (): DateTimeImmutable => $time->deadline(0))
        ->toThrow(InvalidArgumentException::class, 'at least one second');
    expect(static fn (): DateTimeImmutable => $time->deadline(-1))
        ->toThrow(InvalidArgumentException::class, 'at least one second');

    /*
     * The positive control. Without it a deadline() that threw unconditionally --
     * or one whose query was broken on this engine -- would satisfy both refusals
     * above and report this contract as held.
     */
    $now = $time->current();
    $deadline = $time->deadline(1);

    expect($deadline->getTimestamp())->toBeGreaterThanOrEqual($now->getTimestamp() + 1);
});

/* ---- the shared environment helper two security tests now depend on --- */

it('sets and restores an environment variable in all three places Laravel reads', function (): void {
    /*
     * withEnvironmentVariable() became shared infrastructure the moment a second
     * file needed it, and both callers are security tests: #46's asks what a fresh
     * installation gets for the issuance-mutex secret, and the blank-ttl test above
     * asks what a set-but-blank variable becomes. A helper that writes only one of
     * the three adapters makes both of them answer about a variable that was never
     * really changed, and a helper that fails to restore silently changes what every
     * later test in the process reads -- neither of which fails loudly.
     */
    $name = 'VOUCH_TTL_BOUNDS_PROBE';

    expect(getenv($name))->toBeFalse('the probe variable must start absent');

    $seen = withEnvironmentVariable($name, 'probe-value', static fn (): array => [
        getenv($name),
        $_ENV[$name] ?? null,
        $_SERVER[$name] ?? null,
        /*
         * Through Env::get(), which is exactly what the env() helper delegates to
         * and what config/vouch.php therefore reads. Asserted via the class rather
         * than the helper because PHPStan forbids env() outside the config
         * directory, and the phpstan.neon here allows no ignore to get past it.
         */
        Env::get($name),
    ]);

    expect($seen)->toBe(['probe-value', 'probe-value', 'probe-value', 'probe-value']);

    // Restored to ABSENT, not to an empty string: env() distinguishes them, and a
    // variable left behind as '' is exactly the blank-value case under test above.
    expect(getenv($name))->toBeFalse();
    expect(array_key_exists($name, $_ENV))->toBeFalse();
    expect(array_key_exists($name, $_SERVER))->toBeFalse();

    /*
     * And the clearing direction, from a variable that was present. This is the
     * direction #46's test uses, and the one whose restoration failure would leave
     * the issuance secret unset for every test that ran afterwards.
     */
    $cleared = withEnvironmentVariable($name, 'outer', static fn (): mixed => withEnvironmentVariable(
        $name,
        null,
        static fn (): mixed => Env::get($name),
    ));

    expect($cleared)->toBeNull();
    expect(getenv($name))->toBeFalse('the outer scope must restore absence too');
});
