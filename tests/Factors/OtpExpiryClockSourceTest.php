<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Factors\ChallengeRequest;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Tests\Support\CountingHasher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Support\Facades\Hash;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\FixedClock;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

/*
 * #43. The OTP challenge deadline, written by one clock and judged by another.
 *
 * OtpChallengeOutbox writes expires_at through DatabaseTime::deadline(), so the
 * deadline is the database's. OtpFactor::verify() then compares it against the
 * injected PSR clock. The lifetime a user gets is the configured one only while
 * the two machines agree.
 *
 * The blast radius is bounded, which is what makes it easy to miss. The store's
 * guarded consume is already on the database clock, so a stale challenge cannot
 * actually be consumed. What escapes is the OUTCOME NAME: with the application
 * clock lagging, the driver's expiry check still says live, the code compares
 * equal, the guarded consume matches nothing, and the caller is told
 * ChallengeAlreadyConsumed about a challenge nobody ever used. That is a lie
 * with a plausible reading -- a user who sees it concludes their code was
 * stolen and used, when it had merely run out.
 *
 * The other direction is the ordinary one: an application clock ahead refuses a
 * code the database still considers live, and the user retries into the same
 * wall.
 *
 * What these must rule out:
 *
 *   - a fixture that never bound its clock would pass against the real one, so
 *     every skewed test asserts the binding took.
 *   - a driver reading now() or Carbon directly rather than the injected clock
 *     would satisfy an injection-only skew, so both are moved together.
 *   - a "fix" that reported Expired for everything would satisfy the lagging
 *     cases, so the leading cases and the unskewed controls pin acceptance.
 *   - collapsing Expired into Consumed, or the reverse, would satisfy several
 *     of these individually, so a genuinely consumed challenge is checked under
 *     both skews.
 *
 * Nothing asserts HOW the driver reaches the database clock. Delegating the
 * comparison to the store and reading the deadline back are both defensible,
 * and an assertion about the collaborator would reject one of them.
 */

function otpClockDelivery(?ArrayOtpDelivery $bind = null): ArrayOtpDelivery
{
    static $delivery = null;

    if ($bind instanceof ArrayOtpDelivery) {
        $delivery = $bind;
    }

    if (! $delivery instanceof ArrayOtpDelivery) {
        throw new RuntimeException('otpClockDelivery() was read before beforeEach() bound it.');
    }

    return $delivery;
}

beforeEach(function (): void {
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    otpClockDelivery($delivery);
});

afterEach(function (): void {
    Carbon::setTestNow();
});

function otpClockFactor(): EmailOtpFactor
{
    return app(EmailOtpFactor::class);
}

function otpClockDatabaseNow(): DateTimeImmutable
{
    return app(DatabaseTime::class)->current();
}

/**
 * Skew application time N seconds from the database's.
 *
 * Carbon moves with the injected clock deliberately: skewing only the PSR clock
 * would let a driver that calls now() directly pass everything here while still
 * judging a database-written deadline by application time.
 */
function skewOtpClock(int $seconds): FixedClock
{
    $instant = otpClockDatabaseNow()->modify(sprintf('%+d seconds', $seconds));
    $clock = new FixedClock($instant);

    app()->instance(ClockInterface::class, $clock);
    Carbon::setTestNow(Carbon::instance(DateTime::createFromImmutable($instant)));
    app()->forgetInstance(EmailOtpFactor::class);

    return $clock;
}

function assertOtpClockSkewed(FixedClock $clock): void
{
    expect(app(ClockInterface::class))->toBe($clock)
        ->and(Carbon::now()->getTimestamp())->toBe($clock->now()->getTimestamp());
}

function otpClockAttempt(): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 7,
        'bound_context' => 'sess-1',
        'expires_at' => app(DatabaseTime::class)->deadline(600),
    ]);
}

/** Idempotent: a test issuing two challenges enrolls against the same address. */
function otpClockIdentifier(): AuthIdentifier
{
    $existing = AuthIdentifier::query()
        ->where('type', 'email')->where('value', 'ada@acme.example')->first();

    if ($existing instanceof AuthIdentifier) {
        return $existing;
    }

    return AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);
}

/**
 * Issue a challenge and return it with the delivered code.
 *
 * Typed as a shape rather than a bare array: without it every $challenge->id
 * downstream is mixed, findOrFail() widens to a collection union, and the type
 * error lands seven lines away from its cause.
 *
 * @return array{AuthChallenge, string}
 */
function otpClockChallenge(AuthAttempt $attempt): array
{
    $credential = otpClockFactor()
        ->enroll(7, ['identifier_id' => otpClockIdentifier()->id])->credentials[0];

    $challenge = otpClockFactor()->challenge(new ChallengeRequest($attempt, $credential));

    if (! $challenge instanceof AuthChallenge) {
        throw new RuntimeException('Expected an OTP challenge to have been issued.');
    }

    otpClockDelivery()->deliverLatestPending();

    return [$challenge, otpClockDelivery()->lastCode()];
}

/** Whether the database itself still considers that challenge live. */
function liveChallengeOnDatabaseClock(int $id): bool
{
    return DB::table('auth_challenges')
        ->where('id', $id)->whereRaw('expires_at > CURRENT_TIMESTAMP')->exists();
}

it('accepts a code the database still considers live, even when the app clock races ahead', function (): void {
    $attempt = otpClockAttempt();
    [$challenge, $code] = otpClockChallenge($attempt);

    $clock = skewOtpClock(3600);

    /*
     * The availability direction. The database says this code has minutes left;
     * the application says it expired an hour ago, and the user is refused a
     * code that was delivered to them seconds earlier.
     */
    $result = otpClockFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: $challenge,
    ));

    assertOtpClockSkewed($clock);
    expect(liveChallengeOnDatabaseClock($challenge->id))->toBeTrue()
        ->and($result->failure)->toBeNull();
});

it('refuses a code the database has expired, even when the app clock lags', function (): void {
    $attempt = otpClockAttempt();
    [$challenge, $code] = otpClockChallenge($attempt);

    shiftDeadlineOnDatabaseClock('auth_challenges', $challenge->id, -1);
    $clock = skewOtpClock(-3600);

    /*
     * The quiet direction, and the one the store cannot rescue. Its guarded
     * consume refuses correctly, but by then the driver has already said the
     * code was good, so the refusal arrives wearing the wrong name.
     */
    $result = otpClockFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: AuthChallenge::findOrFail($challenge->id),
    ));

    assertOtpClockSkewed($clock);
    expect(liveChallengeOnDatabaseClock($challenge->id))->toBeFalse()
        ->and($result->failure)->toBe(FactorFailure::Expired);
});

it('offers nothing to consume for a challenge the database has expired', function (): void {
    $attempt = otpClockAttempt();
    [$challenge, $code] = otpClockChallenge($attempt);

    shiftDeadlineOnDatabaseClock('auth_challenges', $challenge->id, -1);
    $clock = skewOtpClock(-3600);

    /*
     * The mis-named outcome, stated as the thing that causes it. A result that
     * carries a ConsumeChallenge for an expired challenge is what reaches the
     * store, matches nothing, and comes back as ChallengeAlreadyConsumed. The
     * challenge must also still be unconsumed afterwards: "already consumed"
     * was never true of it.
     */
    $result = otpClockFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: AuthChallenge::findOrFail($challenge->id),
    ));

    assertOtpClockSkewed($clock);
    expect($result->mutations)->toBe([])
        ->and(AuthChallenge::findOrFail($challenge->id)->consumed_at)->toBeNull();
});

it('still refuses a consumed challenge as consumed, under either skew', function (int $skew): void {
    $attempt = otpClockAttempt();
    [$challenge, $code] = otpClockChallenge($attempt);

    AuthChallenge::query()->whereKey($challenge->id)
        ->update(['consumed_at' => app(DatabaseTime::class)->current()]);

    /*
     * Expired on the database clock AS WELL as consumed. Marking consumption
     * alone left the deadline live, so once expiry moves onto the database
     * clock nothing in this test established expiry at all and the precedence
     * it claims to pin went unexercised -- an expiry-first implementation
     * passed it.
     */
    shiftDeadlineOnDatabaseClock('auth_challenges', $challenge->id, -1);

    $clock = skewOtpClock($skew);

    /*
     * Expired and Consumed are different facts with different remedies, and a
     * fix that collapsed either into the other would satisfy several of the
     * tests above on its own. Consumption is checked before expiry today and
     * that ordering is preserved: a challenge that was used and has since run
     * out is still, first, one that was used.
     */
    $result = otpClockFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $code],
        challenge: AuthChallenge::findOrFail($challenge->id),
    ));

    assertOtpClockSkewed($clock);
    expect($result->failure)->toBe(FactorFailure::Consumed);
})->with(['app clock ahead' => [3600], 'app clock behind' => [-3600]]);

it('spends no hashing on a wrong code against a dead challenge', function (): void {
    $attempt = otpClockAttempt();
    [$challenge, $code] = otpClockChallenge($attempt);

    shiftDeadlineOnDatabaseClock('auth_challenges', $challenge->id, -1);

    /*
     * Hash::swap, not a container instance() binding. The driver reaches the
     * hasher through the Hash facade's HashManager, which caches its own
     * driver, so rebinding Hasher::class left production hashing through the
     * real one and this counter reading zero no matter what -- it passed a
     * hash-before-expiry implementation on every run when measured.
     */
    $hasher = new CountingHasher(otpClockRealHasher());
    Hash::swap($hasher);
    app()->forgetInstance(EmailOtpFactor::class);

    /*
     * The outcome alone proves nothing about ordering. The throttle path
     * detects expiry independently and restores Expired AFTER the comparison,
     * so an implementation that hashed first passed the outcome assertion --
     * measured. Counting the checks is what separates the two.
     *
     * A code guaranteed different from the issued one, not six zeroes: that is
     * a value the generator can legitimately produce, and this test would then
     * silently become a right-code test roughly once in a million runs.
     */
    $result = otpClockFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => otpClockOtherCode($code)],
        challenge: AuthChallenge::findOrFail($challenge->id),
    ));

    expect($result->failure)->toBe(FactorFailure::Expired)
        ->and($hasher->checks)->toBe(0);
});

it('does hash a wrong code against a live challenge', function (): void {
    $attempt = otpClockAttempt();
    [$challenge, $code] = otpClockChallenge($attempt);

    $hasher = new CountingHasher(otpClockRealHasher());
    Hash::swap($hasher);
    app()->forgetInstance(EmailOtpFactor::class);

    /*
     * The positive control for the counter above. Without it, a counter wired
     * to something production never calls reads zero for the right reason and
     * the wrong one alike, and the ordering test becomes decoration.
     */
    $result = otpClockFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => otpClockOtherCode($code)],
        challenge: $challenge,
    ));

    expect($result->failure)->toBe(FactorFailure::Mismatch)
        ->and($hasher->checks)->toBeGreaterThan(0);
});

/**
 * The hasher production actually uses, narrowed by a real check.
 *
 * getFacadeRoot() is mixed, and the alternatives level 9 leaves are a
 * suppression or an inline annotation, both of which phpstan.neon forbids for
 * the same reason: they assert the thing instead of establishing it.
 */
function otpClockRealHasher(): Hasher
{
    $hasher = Hash::getFacadeRoot();

    if (! $hasher instanceof Hasher) {
        throw new RuntimeException('The Hash facade did not resolve a hasher.');
    }

    return $hasher;
}

/** A code of the same shape as $code and guaranteed not equal to it. */
function otpClockOtherCode(string $code): string
{
    $digits = str_split($code);
    $digits[0] = (string) (((int) $digits[0] + 1) % 10);

    return implode('', $digits);
}

it('accepts a live code and refuses a dead one while both clocks agree', function (): void {
    $attempt = otpClockAttempt();
    [$live, $liveCode] = otpClockChallenge($attempt);

    // The unskewed control. Without it, a driver that reported Expired for
    // everything would satisfy every lagging case above.
    $accepted = otpClockFactor()->verify(new VerificationRequest(
        attempt: $attempt,
        input: ['code' => $liveCode],
        challenge: $live,
    ));

    $second = otpClockAttempt();
    [$dead, $deadCode] = otpClockChallenge($second);
    shiftDeadlineOnDatabaseClock('auth_challenges', $dead->id, -1);

    $refused = otpClockFactor()->verify(new VerificationRequest(
        attempt: $second,
        input: ['code' => $deadCode],
        challenge: AuthChallenge::findOrFail($dead->id),
    ));

    expect($accepted->failure)->toBeNull()
        ->and($refused->failure)->toBe(FactorFailure::Expired);
});

it('treats a challenge as dead at its deadline, not merely after it', function (): void {
    if (DB::connection()->getDriverName() !== 'sqlite') {
        $this->markTestSkipped(
            'Constructing the exact instant needs a database clock that can be held still.',
        );
    }

    $attempt = otpClockAttempt();
    [$challenge, $code] = otpClockChallenge($attempt);

    /*
     * The one place the <= boundary is still provable, and it is worth the
     * trouble: the difference between <= and < is whether a code keeps working
     * for one more second after the deadline it was issued with.
     *
     * Setting the deadline to database now does not construct it -- the clock
     * moves between the update and the read, so both operators agree. Holding
     * the database's own clock still at exactly the deadline is what separates
     * them, and SQLite is the engine that will let a test do that.
     *
     * Skipped elsewhere rather than approximated, because an approximation
     * here reads as coverage while discriminating nothing.
     */
    $deadline = $challenge->expires_at->toDateTimeImmutable();
    $now = $deadline->modify('-1 second')->format('Y-m-d H:i:s');

    $pdo = DB::connection()->getPdo();
    $pdo->sqliteCreateFunction('current_timestamp', static function () use (&$now): string {
        return $now;
    }, 0);

    try {
        /*
         * A PAIR against one challenge, one deadline and one factor instance,
         * which is what makes it do two jobs.
         *
         * The second half is the <= boundary. The first half is what catches a
         * driver that reads the database clock once and keeps it: having
         * answered "live" here, it must not answer "live" again after the clock
         * has reached the deadline. Moving the deadline instead cannot
         * distinguish those, because a stale reading and a fresh one are both
         * behind a deadline that moved backwards.
         */
        expect(otpClockFactor()->verify(new VerificationRequest(
            attempt: $attempt,
            input: ['code' => $code],
            challenge: $challenge,
        ))->failure)->toBeNull();

        $now = $deadline->format('Y-m-d H:i:s');

        // The premise, asserted rather than assumed: the database really does
        // now read its own clock as exactly this challenge's deadline.
        $exact = requiredRow(DB::selectOne(
            'SELECT expires_at = CURRENT_TIMESTAMP AS exact FROM auth_challenges WHERE id = ?',
            [$challenge->id],
        ));

        expect($exact->exact)->toBe(1);

        expect(otpClockFactor()->verify(new VerificationRequest(
            attempt: $attempt,
            input: ['code' => $code],
            challenge: $challenge,
        ))->failure)->toBe(FactorFailure::Expired);
    } finally {
        /*
         * This restores a PHP stand-in rather than SQLite's built-in, which
         * cannot be uninstalled once overridden. Measured as not leaking --
         * Testbench rebuilds the connection between tests -- but worth stating,
         * because the stand-in can return different values within one statement
         * where the native function does not.
         */
        $pdo->sqliteCreateFunction(
            'current_timestamp',
            static fn (): string => gmdate('Y-m-d H:i:s'),
            0,
        );
    }
});
