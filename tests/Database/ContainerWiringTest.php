<?php

declare(strict_types=1);

use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Http\FlowResultSerializer;
use Fissible\Vouch\Http\IntendedDestination;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * The service provider's registration lists, which nothing asserted.
 *
 * A driver dropped from the registry list does not fail loudly: the factor is
 * simply absent, so a policy naming it raises UnknownFactor and a user enrolled
 * in it can no longer authenticate. That is a silent loss of authentication
 * capability, arriving from a list nobody reads.
 */

it('registers every shipped factor driver', function (): void {
    /*
     * Asserted as an exact set, not a subset. A missing entry is the failure
     * this exists for, and an unexpected extra entry means a driver reached the
     * registry without passing through this list -- which the write-once design
     * exists to make impossible.
     */
    $ids = array_map(
        static fn (\Fissible\Vouch\Contracts\Factor $factor): string => $factor->id(),
        app(FactorRegistry::class)->all(),
    );

    sort($ids);

    expect($ids)->toBe(['email_otp', 'password', 'recovery_code', 'sms_otp', 'totp']);
});

it('resolves every singleton the provider registers as one shared instance', function (string $class): void {
    /*
     * Registered in a loop, so a dropped entry is invisible at the call site --
     * the class still resolves, just not as the shared instance the rest of the
     * request is using.
     *
     * The dataset below once named three of the provider's singletons while
     * the test's name promised all of them, and the gap was not academic: the
     * mutation gate killed the three that were listed and left the other eight
     * registrations that nothing else covers surviving. Dropping any one of them
     * leaves a class that still resolves -- Laravel autowires most of these --
     * but hands a fresh instance to every caller, so shared state registered
     * once per request silently becomes per-resolution state.
     *
     * Kept as an exact enumeration rather than derived from the provider, for
     * the same reason the factor-driver list above is: a list derived from the
     * thing under test cannot detect that the thing under test lost an entry.
     */
    expect(app($class))->toBe(app($class));
})->with([
    // Bound by class name in the foreach loop.
    IntendedDestination::class,
    FlowResultSerializer::class,
    AssuranceComparator::class,
    // Bound with explicit construction closures.
    \Fissible\Vouch\Contracts\AttemptStore::class,
    \Fissible\Vouch\Enrollment\EnrollmentGuard::class,
    \Fissible\Vouch\Flow\ScreenBuilder::class,
    \Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary::class,
    \Fissible\Vouch\Flow\AuthFlow::class,
    \Fissible\Vouch\Sessions\SessionLifecycle::class,
    \Fissible\Vouch\Support\DatabaseTime::class,
    \Fissible\Vouch\Support\BoundedLockWait::class,
    \Fissible\Vouch\Support\LockContention::class,
    \Fissible\Vouch\Recovery\GraceGuard::class,
    // FlowResultHandler is NOT here: it needs a StatefulGuard, which the test
    // application does not bind. It has its own test below rather than being
    // quietly dropped from this list -- a singleton omitted from an exhaustive
    // enumeration is the exact defect this test exists to catch.
    // The five factor drivers and the registry that resolves them.
    \Fissible\Vouch\Factors\Drivers\PasswordFactor::class,
    \Fissible\Vouch\Factors\Drivers\TotpFactor::class,
    \Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class,
    \Fissible\Vouch\Factors\Drivers\EmailOtpFactor::class,
    \Fissible\Vouch\Factors\Drivers\SmsOtpFactor::class,
    FactorRegistry::class,
    // Bound as an interface-to-implementation pair.
    \Psr\Clock\ClockInterface::class,
]);

it('resolves the flow result handler as one shared instance too', function (): void {
    /*
     * Separated from the enumeration above only because its construction pulls
     * a StatefulGuard and a Session, which the test application does not bind by
     * default. Binding the guard here is setup, not the assertion: what is being
     * asserted is the same shared-instance contract every other singleton gets.
     */
    $guard = auth()->guard('web');

    // A real check rather than a cast, matching the convention in
    // ProviderEffectTest: that the web guard is stateful is a premise of this
    // test, so say so where it would otherwise be assumed.
    if (! $guard instanceof \Illuminate\Contracts\Auth\StatefulGuard) {
        throw new RuntimeException('The web guard is not stateful; this test needs one.');
    }

    app()->bind(\Illuminate\Contracts\Auth\StatefulGuard::class, static fn (): \Illuminate\Contracts\Auth\StatefulGuard => $guard);

    expect(app(\Fissible\Vouch\Http\FlowResultHandler::class))
        ->toBe(app(\Fissible\Vouch\Http\FlowResultHandler::class));
});

it('prunes revoked sessions on the documented retention window and not before', function (): void {
    /*
     * `now()->subDays($retentionDays)` with a default of 30. Both the default and
     * the arithmetic are load-bearing in the same direction: too small, and
     * revoked-session records -- the audit trail of every forced logout and
     * administrative revocation -- are deleted while an investigation might still
     * need them.
     *
     * Asserted from both sides of the boundary, because a one-sided test cannot
     * tell a 30-day window from a 3-day one.
     */
    // NOT set here, deliberately. Setting it to 30 would read the caller's value
    // and never the default -- the test would pass with the default changed to
    // anything at all, which is exactly how the TOTP defaults test first failed
    // to test defaults.
    $keep = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('k', 64), 'user_id' => 7, 'amr' => json_encode(['password']),
        'revoked_at' => now()->subDays(29), 'created_at' => now(), 'updated_at' => now(),
    ]);
    $drop = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('d', 64), 'user_id' => 7, 'amr' => json_encode(['password']),
        'revoked_at' => now()->subDays(31), 'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(DB::table('auth_sessions')->where('id', $keep)->exists())->toBeTrue()
        ->and(DB::table('auth_sessions')->where('id', $drop)->exists())->toBeFalse();
});

it('ships a retention window in config, which is the value actually used', function (): void {
    /*
     * VouchPruneCommand reads Config::integer(key, 30), and that inline 30 is
     * UNREACHABLE: the package config always supplies the key via
     * mergeConfigFrom, so the fallback never fires. Its mutants are therefore
     * equivalent -- conditional on the config file continuing to ship the key,
     * which is what this asserts.
     *
     * The live default is the one in config/vouch.php. Duplicating it at the call
     * site is a second statement of the same invariant, and only one of the two
     * is real; this test names which.
     */
    expect(config('vouch.sessions.revocation_retention_days'))->toBe(30);
});

it('honours a configured retention window over the default', function (): void {
    // The other half: the default is read when nothing is set, and a configured
    // value is read when it is. Only the pair pins both.
    Config::set('vouch.sessions.revocation_retention_days', 3);

    $drop = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('c', 64), 'user_id' => 7, 'amr' => json_encode(['password']),
        'revoked_at' => now()->subDays(5), 'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    // Five days old: kept under the 30-day default, pruned under the configured 3.
    expect(DB::table('auth_sessions')->where('id', $drop)->exists())->toBeFalse();
});

it('never prunes a session that is still live', function (): void {
    /*
     * revoked_at IS NULL means an active session.
     *
     * The whereNotNull() predicate is dispositioned EQUIVALENT rather than
     * pinned, and the reason is SQL null semantics: `NULL <= <date>` evaluates to
     * NULL, never true, so an unrevoked row can never satisfy the retention
     * comparison whether or not the predicate is present. Probed -- removing it
     * leaves this test green, and no test could distinguish it.
     *
     * The predicate stays: it states the intent at the query, and it is the arm
     * that would still hold if the comparison were ever rewritten.
     */
    $live = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('l', 64), 'user_id' => 7, 'amr' => json_encode(['password']),
        'revoked_at' => null, 'created_at' => now()->subYear(), 'updated_at' => now()->subYear(),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    expect(DB::table('auth_sessions')->where('id', $live)->exists())->toBeTrue();
});

it('reports what it pruned', function (): void {
    /*
     * The command's output is the only record an operator gets of how many
     * security records were destroyed. A prune that deletes silently leaves no
     * account of itself: nothing in the database says what was removed, because
     * removal is the point.
     *
     * The counts are asserted, not merely that something was printed -- "Pruned 0
     * attempt(s)" and "Pruned 40 attempt(s)" are very different operational
     * facts, and a message that always said zero would be worse than none.
     */
    DB::table('auth_attempts')->insert([
        'handle' => bin2hex(random_bytes(32)),
        'state' => \Fissible\Vouch\Kernel\Attempt\AttemptState::Initiated->value,
        'bound_context' => str_repeat('p', 64),
        'expires_at' => now()->subMinute(),
        'created_at' => now(), 'updated_at' => now(),
    ]);
    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('q', 64), 'user_id' => 7, 'amr' => json_encode(['password']),
        'revoked_at' => now()->subDays(40), 'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(Artisan::call('vouch:prune'))->toBe(0);

    $output = Artisan::output();

    expect($output)->toContain('1 attempt(s)')
        ->and($output)->toContain('1 revoked session(s)');
});
