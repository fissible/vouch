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
    // Registered in a loop, so a dropped entry is invisible at the call site --
    // the class still resolves, just not as the shared instance the rest of the
    // request is using.
    expect(app($class))->toBe(app($class));
})->with([IntendedDestination::class, FlowResultSerializer::class, AssuranceComparator::class]);

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
