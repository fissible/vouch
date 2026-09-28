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
 * Every Vouch-namespaced singleton is forgotten first, rather than a named few.
 * The provider resolves its validating services eagerly during boot, so an
 * instance left over from the test application's own boot would answer from the
 * configuration this test just replaced -- and naming the services would pin WHICH
 * object carries the check. Measured: naming ThrottleConfiguration and AuthFlow
 * alone makes a correct implementation that validates through any other eagerly
 * resolved singleton indistinguishable from no implementation at all.
 *
 * app()->forgetInstances() is not the shortcut it looks like: it drops the
 * container's aliases too, so boot() then dies with BindingResolutionException for
 * reasons that have nothing to do with the TTL.
 */
function bootWithAttemptTtl(mixed $value): void
{
    Config::set('vouch.attempts.ttl_seconds', $value);

    foreach (array_keys(app()->getBindings()) as $abstract) {
        if (is_string($abstract) && str_starts_with($abstract, 'Fissible\\Vouch\\')) {
            app()->forgetInstance($abstract);
        }
    }

    (new VouchServiceProvider(app()))->boot();
}

/** The one sentence the package uses to refuse a setting that must be a positive integer. */
function attemptTtlRefusal(string $described): string
{
    return 'Configuration "vouch.attempts.ttl_seconds" must be a positive integer; got ' . $described . '.';
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

    /*
     * And the shipped value actually boots, rather than merely being positive in
     * isolation. Nothing is asserted about the container afterwards on purpose: any
     * such assertion would either be a tautology or would name whichever object
     * happens to carry the check.
     */
    bootWithAttemptTtl($shipped);
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
        /*
         * The whole sentence, as ProviderEffectTest pins it for the sibling throttle
         * setting. Asserting only that the message CONTAINS the value is vacuous for
         * the case this issue is mostly about: (string) 0 is "0", and a zero appears
         * incidentally in almost any bounds message -- measured, a message naming no
         * value at all but mentioning a range of 86400 satisfies it.
         *
         * Pinning the wording does not pin a class. The package has one sentence for
         * this refusal; a second, differently worded one for a sibling setting would
         * be the defect, whoever emits it.
         */
        expect($failure->getMessage())->toBe(attemptTtlRefusal((string) $seconds));
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
        // The value named here too. This is the case where what the operator SET is
        // not what arrived, which is precisely where a message without it misleads.
        expect($failure->getMessage())->toBe(attemptTtlRefusal('0'));
    }
});

it('fails boot on an attempt ttl that is not an integer', function (mixed $value, string $described): void {
    /*
     * The same defect with a different trigger, and the reason it belongs here: the
     * read at the AuthFlow construction site is config()->integer(), which refuses a
     * non-integer at REQUEST time. So a published config whose expression lost the
     * (int) cast -- `env('VOUCH_ATTEMPT_TTL', 600)` -- boots cleanly and then 500s
     * every login with no attempt insert, which is #55's symptom exactly.
     *
     * Measured, and this is why the datasets are here: a boot check that validates
     * only positivity accepts the string "600", because the package's positive-value
     * reader deliberately accepts numeric strings for the throttle settings that are
     * read without a cast. That check leaves this whole class of values behind while
     * every other test in this file passes.
     */
    try {
        bootWithAttemptTtl($value);

        throw new RuntimeException('Provider boot accepted a non-integer attempt ttl: ' . $described . '.');
    } catch (InvalidArgumentException $failure) {
        expect($failure->getMessage())->toBe(attemptTtlRefusal($described));
    }
})->with([
    // A positive number that is not an integer: accepted by a positivity-only check,
    // refused by config()->integer() once a request arrives.
    'a numeric string' => ['600', 'string "600"'],
    'an empty string' => ['', 'an empty string'],
    'null' => [null, 'null'],
    'an array' => [[], 'array'],
    'a float' => [600.0, 'float'],
    'a boolean' => [true, 'bool'],
]);

/* ---- the diagnostic command must survive what it exists to report ----- */

it('lets vouch:doctor boot on an attempt ttl it otherwise refuses', function (): void {
    /*
     * The provider exempts vouch:doctor from the CAPTCHA and issuance-secret checks
     * for a reason that applies here unchanged: the one command whose job is to TELL
     * an operator what is misconfigured must not be the command a misconfiguration
     * stops from running. A blank VOUCH_ATTEMPT_TTL is precisely the situation in
     * which somebody reaches for it.
     *
     * Measured against an implementation with no exemption: boot throws under
     * vouch:doctor argv, and the whole suite stays green -- nothing else notices.
     */
    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:doctor'];

        // Must not throw. An exception here fails the test by itself; the control
        // below is what proves this is an exemption rather than an absent check.
        bootWithAttemptTtl(0);

        /*
         * The control, in the same test so the two cannot drift apart: the identical
         * value under ordinary argv must still be refused. Without it, deleting the
         * boot check entirely would satisfy the exemption above.
         */
        $_SERVER['argv'] = ['artisan', 'about'];

        expect(static fn (): null => bootWithAttemptTtl(0))
            ->toThrow(InvalidArgumentException::class, attemptTtlRefusal('0'));
    } finally {
        if ($original === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $original;
        }
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

    // Narrowed by a guard rather than by expect()->toBeInstanceOf(), which reads
    // like a type assertion but narrows nothing for the static analyser.
    if (! $begun instanceof Continuing) {
        throw new RuntimeException('The flow refused to begin an attempt on a valid ttl.');
    }

    $after = app(DatabaseTime::class)->current();

    // By the handle the flow reported, not by the newest id: the assertion should be
    // about the row this call created rather than about whatever was written last.
    $attempt = DB::table('auth_attempts')->where('handle', stringValue($begun->handle))->first();
    $deadline = new DateTimeImmutable(stringValue(requiredRow($attempt)->expires_at));

    /*
     * Bracketed against the database clock either side of the write, with a second
     * of slack at each end -- the same tolerance the merged sibling uses for this
     * column on this clock.
     *
     * The slack is not caution, it is required. Under RefreshDatabase the test runs
     * inside one transaction, and PostgreSQL's CURRENT_TIMESTAMP is the
     * TRANSACTION's start, so $before and $after are the same instant and the
     * bracket has zero width -- while deadlineSql('pgsql') uses
     * CURRENT_TIMESTAMP(0), which ROUNDS, and getTimestamp() truncates. Measured
     * without the slack: seven consecutive PostgreSQL runs, seven failures, always
     * exactly one second above the upper bound.
     *
     * A second of slack on a 137-second window still rejects a stale 600.
     */
    expect($deadline->getTimestamp())->toBeGreaterThanOrEqual($before->getTimestamp() + TTL_BOUNDS_VALID - 1);
    expect($deadline->getTimestamp())->toBeLessThanOrEqual($after->getTimestamp() + TTL_BOUNDS_VALID + 1);
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
