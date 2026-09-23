<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Tests\Support\FixedClock;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

/*
 * #44. The attempt deadline, written on one clock and judged on another.
 *
 * This is #37's seam pointing the other way. There, a deadline written with
 * DatabaseTime was compared against PHP time. Here the write is the
 * application's -- AuthFlow::begin() stores clock->now() plus the TTL -- while
 * every reader evaluates it against CURRENT_TIMESTAMP: the store's guarded
 * advance, its expired-or-lost-race discriminator, and the prune command.
 *
 * So the correction belongs to the WRITE. The readers are already on the right
 * authority and must stay there, which is why some of these tests exist to
 * refuse a "fix" that moved them instead.
 *
 * Both directions, because they fail differently:
 *
 *   - an application clock running BEHIND the database shortens every window
 *     by the offset, and once the offset exceeds the TTL the attempt is born
 *     expired. Loud, and it denies service to everyone at once.
 *   - one running AHEAD lengthens every window by the offset. Quiet, and it is
 *     the security side: an attempt stays advanceable long after the window it
 *     was supposed to have.
 *
 * What these must rule out, and how:
 *
 *   - a fixture that never bound its clock would pass against the real one, so
 *     every skewed test asserts the binding took.
 *   - an implementation reading now() or Carbon directly rather than the
 *     injected PSR clock would satisfy an injection-only skew, so both are
 *     moved together.
 *   - a write that drops the interval, or shortens it, survives any test that
 *     only asks whether a fresh attempt is live. The window is therefore
 *     measured, with both bounds, against a TTL configured to something other
 *     than the default -- a writer hard-coded to the default passes otherwise.
 *   - the window assertions describe what was WRITTEN and say nothing about
 *     what judges it. Moving the readers onto application time reintroduces
 *     the crossing in mirror image, and only the behavioral guards catch it:
 *     a live attempt must stay advanceable with the app clock far ahead, and
 *     an expired one must stay refused with it far behind.
 *   - moving only expiredOrLostRace() would leave the guarded update refusing
 *     correctly while naming the wrong reason, so the two outcomes are
 *     asserted directly rather than through the flow.
 *
 * Nothing asserts that DatabaseTime was CONSULTED. A correct fix might express
 * the deadline in the INSERT itself or read it back and bind it; both put the
 * deadline on the database's authority, and an assertion about the collaborator
 * would reject one of them.
 *
 * Two limits, stated rather than implied. These freeze the injected PSR clock
 * and Carbon, so a writer reaching for PHP's native clock -- new
 * DateTimeImmutable('now') -- passes everything here. And they say nothing
 * about the 37 fixture writes across the suite that set expires_at from now()
 * directly; those are not this change's business, and fixing begin() does not
 * touch them.
 */

/*
 * Deliberately not the configured default of 600. A writer that hard-coded the
 * default measured correctly against a test that also used it.
 */
const ATTEMPT_TTL = 137;

/**
 * Configure the attempt window, and make the flow pick the new value up.
 *
 * The key is 'attempts', plural, which is what the container reads. Setting
 * 'attempt' writes a key nobody consults, and an assertion that reads the same
 * wrong key passes while the flow keeps the default -- which is how the first
 * version of this file quietly measured 600 against an expectation of 137.
 * The window assertions are the real proof the value took: they fail loudly if
 * this ever stops reaching AuthFlow.
 */
function useAttemptTtl(int $seconds): void
{
    Config::set('vouch.attempts.ttl_seconds', $seconds);
    app()->forgetInstance(AuthFlow::class);

    expect(Config::integer('vouch.attempts.ttl_seconds'))->toBe($seconds)
        ->and($seconds)->not->toBe(600);
}

beforeEach(function (): void {
    useAttemptTtl(ATTEMPT_TTL);
});

function attemptBinding(): string
{
    return str_repeat('d', 64);
}

/** The database's own current time, through the package's accessor. */
function attemptDatabaseNow(): DateTimeImmutable
{
    return app(DatabaseTime::class)->current();
}

/**
 * Skew application time N seconds from the database's.
 *
 * Carbon moves with the PSR clock deliberately: skewing only the injected clock
 * would let an implementation that calls now() directly pass everything here
 * while still writing application time.
 */
function skewAppClock(int $seconds): FixedClock
{
    $instant = attemptDatabaseNow()->modify(sprintf('%+d seconds', $seconds));
    $clock = new FixedClock($instant);

    app()->instance(ClockInterface::class, $clock);
    Carbon::setTestNow(Carbon::instance(DateTime::createFromImmutable($instant)));
    app()->forgetInstance(AuthFlow::class);

    return $clock;
}

/** Both application clocks really are the skewed one. */
function assertAppClockSkewed(FixedClock $clock): void
{
    expect(app(ClockInterface::class))->toBe($clock)
        ->and(Carbon::now()->getTimestamp())->toBe($clock->now()->getTimestamp());
}

afterEach(function (): void {
    Carbon::setTestNow();
});

function beginAttempt(): string
{
    $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], attemptBinding()));

    /*
     * Narrowed by a real check rather than an expectation: a flow that stopped
     * returning Continuing would otherwise surface as a property error on the
     * next line, which reads like a test defect rather than the behavior change
     * it would be.
     */
    if (! $begun instanceof Continuing) {
        throw new RuntimeException('The flow refused to begin an attempt.');
    }

    return stringValue($begun->handle);
}

function attemptRow(string $handle): AuthAttempt
{
    return AuthAttempt::query()->where('handle', $handle)->firstOrFail();
}

/** The deadline stored for an attempt, as the database holds it. */
function attemptDeadline(string $handle): DateTimeImmutable
{
    return new DateTimeImmutable(stringValue(
        DB::table('auth_attempts')->where('handle', $handle)->value('expires_at'),
    ));
}

/**
 * Bracket the stored deadline against database time sampled either side of the
 * write.
 *
 * A single "now" read afterwards cannot separate two different things: the
 * seconds that elapsed during the INSERT, and one second of storage precision.
 * PostgreSQL rounds CURRENT_TIMESTAMP(0) while getTimestamp() truncates, so a
 * correct write lands a second either side of the arithmetic often enough to
 * fail a fixed bound -- measured on PostgreSQL, where a correct implementation
 * failed at 601 <= 600 on several runs out of every few.
 *
 * Bracketing keeps the assertion tight where it matters, but be honest about
 * its resolution: a TTL wrong by one second always survives, and wrong by two
 * has survived a whole PostgreSQL run, where rounding supplies one second and
 * the tolerance the other -- no slow machine required. This guards the CLOCK
 * the deadline was written from, not the exactness of the interval. The
 * configured-TTL tests pin the value, and they carry the same tolerance.
 */
function expectWindowOnDatabaseClock(
    string $handle,
    DateTimeImmutable $before,
    DateTimeImmutable $after,
    int $ttl,
): void {
    $stored = attemptDeadline($handle)->getTimestamp();

    expect($stored)->toBeGreaterThanOrEqual($before->getTimestamp() + $ttl - 1)
        ->and($stored)->toBeLessThanOrEqual($after->getTimestamp() + $ttl + 1);
}

function submitIdentifier(string $handle): void
{
    app(AuthFlow::class)->advance(
        new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], attemptBinding()),
    );
}

function recognisedIdentifier(): void
{
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);
    app(PasswordFactor::class)->enroll(1, ['password' => 'old-password']);
}

it('gives an attempt the configured window measured on the database clock', function (int $skew): void {
    $clock = skewAppClock($skew);

    /*
     * Both bounds. A lower bound alone passes an application clock running
     * ahead, which is the quiet direction; an upper bound alone passes one
     * running behind.
     */
    $before = attemptDatabaseNow();
    $handle = beginAttempt();
    $after = attemptDatabaseNow();

    assertAppClockSkewed($clock);
    expectWindowOnDatabaseClock($handle, $before, $after, ATTEMPT_TTL);
})->with([
    'app clock far behind' => [-(ATTEMPT_TTL + 120)],
    'app clock slightly behind' => [-30],
    'clocks agree' => [0],
    'app clock slightly ahead' => [30],
    'app clock far ahead' => [3600],
]);

it('advances an attempt begun while the application clock lagged', function (): void {
    recognisedIdentifier();
    $clock = skewAppClock(-(ATTEMPT_TTL + 120));

    $handle = beginAttempt();

    /*
     * The loud direction, stated as behavior rather than as a column value.
     * With the write on application time this attempt is born expired on the
     * database clock, the guarded advance matches nothing, and the user cannot
     * get past the first screen no matter how quickly they answer.
     */
    submitIdentifier($handle);

    assertAppClockSkewed($clock);
    expect(attemptRow($handle)->state)->not->toBe(AttemptState::Initiated)
        ->and(attemptRow($handle)->version)->toBeGreaterThan(1);
});

it('refuses an attempt the database has expired', function (): void {
    recognisedIdentifier();

    $handle = beginAttempt();
    shiftDeadlineOnDatabaseClock('auth_attempts', attemptRow($handle)->id, -1);

    /*
     * The unskewed control. It overlaps the lagged case deliberately: if the
     * guard itself were removed, the skewed tests would still have a plausible
     * reading as clock problems, and this one would not.
     */
    submitIdentifier($handle);

    expect(attemptRow($handle)->state)->toBe(AttemptState::Initiated)
        ->and(attemptRow($handle)->version)->toBe(1);
});

it('keeps advancing a live attempt while the application clock races ahead', function (): void {
    recognisedIdentifier();

    $handle = beginAttempt();
    $clock = skewAppClock(ATTEMPT_TTL * 10);

    /*
     * The readers are already on the database clock and must stay there. The
     * window assertions say nothing about this -- they describe what was
     * written, not what judges it -- so this guard and its mirror below are the
     * only things standing between a correct write and the same crossing
     * rebuilt on the reading side.
     */
    submitIdentifier($handle);

    assertAppClockSkewed($clock);
    expect(attemptRow($handle)->state)->not->toBe(AttemptState::Initiated);
});

it('keeps refusing an expired attempt while the application clock lags', function (): void {
    recognisedIdentifier();

    $handle = beginAttempt();
    shiftDeadlineOnDatabaseClock('auth_attempts', attemptRow($handle)->id, -1);
    $clock = skewAppClock(-(ATTEMPT_TTL * 10));

    // The paired direction of the same guard: application time says plenty of
    // room, the database says the window closed, and the database decides.
    submitIdentifier($handle);

    assertAppClockSkewed($clock);
    expect(attemptRow($handle)->state)->toBe(AttemptState::Initiated)
        ->and(attemptRow($handle)->version)->toBe(1);
});

it('prunes attempts on the database clock, not the application one', function (): void {
    $live = attemptRow(beginAttempt());

    $expiredHandle = beginAttempt();
    $expired = attemptRow($expiredHandle);
    shiftDeadlineOnDatabaseClock('auth_attempts', $expired->id, -1);

    $clock = skewAppClock(ATTEMPT_TTL * 10);

    /*
     * Housekeeping has to agree with the guard about which attempts are over.
     * Deleting on a different authority than the one that decides liveness
     * either removes rows a request could still advance, or leaves rows the
     * store will never accept again.
     */
    expect(Artisan::call('vouch:prune'))->toBe(0);

    assertAppClockSkewed($clock);
    expect(AuthAttempt::query()->whereKey($expired->id)->exists())->toBeFalse()
        ->and(AuthAttempt::query()->whereKey($live->id)->exists())->toBeTrue();
});

it('names an expired attempt expired, not a lost race', function (): void {
    /*
     * Skewed BEFORE the attempt begins, deliberately. Skewing afterwards lets
     * the store be resolved against the real clock first, and a discriminator
     * that snapshotted ClockInterface::now() in its constructor then passed
     * every case here -- measured. Retaining the clock OBJECT was caught; the
     * snapshot was not.
     */
    $clock = skewAppClock(-(ATTEMPT_TTL * 10));

    $handle = beginAttempt();
    $attempt = attemptRow($handle);
    shiftDeadlineOnDatabaseClock('auth_attempts', $attempt->id, -1);

    /*
     * Asserted on the store rather than through the flow, because the flow
     * folds both refusals into the same screen. Moving ONLY the
     * expired-or-lost-race discriminator onto application time leaves the
     * guarded update refusing correctly and passes every other test here --
     * measured -- while telling the caller its attempt lost a race it never
     * entered. The store's own comment says the caller deserves to know which.
     */
    $outcome = app(AttemptStore::class)->transition($attempt, AttemptState::Identified);

    assertAppClockSkewed($clock);
    expect($outcome)->toBe(TransitionOutcome::Expired);
});

it('names a stale version a lost race, not an expiry', function (): void {
    $clock = skewAppClock(ATTEMPT_TTL * 10);

    $handle = beginAttempt();
    $attempt = attemptRow($handle);

    // Someone else advanced it first. The row is live; this caller's copy is
    // simply behind, which is a different refusal with a different remedy.
    DB::table('auth_attempts')->where('id', $attempt->id)
        ->update(['version' => $attempt->version + 1]);

    $outcome = app(AttemptStore::class)->transition($attempt, AttemptState::Identified);

    assertAppClockSkewed($clock);
    expect($outcome)->toBe(TransitionOutcome::ConcurrentModification);
});

it('measures whatever window is configured, not one particular value', function (): void {
    /*
     * A writer hard-coded to the default passed when the file used the default,
     * and one hard-coded to 137 passed once the file used 137. Only a second
     * configured value distinguishes "reads the setting" from "happens to match
     * the number this file chose".
     */
    useAttemptTtl(271);

    $before = attemptDatabaseNow();
    $handle = beginAttempt();
    $after = attemptDatabaseNow();

    expectWindowOnDatabaseClock($handle, $before, $after, 271);
});
