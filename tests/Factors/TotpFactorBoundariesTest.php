<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Fissible\Vouch\Support\SystemClock;
use OTPHP\TOTP;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

/*
 * The behaviour the existing TotpFactorTest does not reach: the constructor's
 * validation boundaries, the defaults themselves, enroll()'s label and replace
 * contracts, and the two ways verify() can find nothing to verify against.
 *
 * These surfaced as mutation survivors, and they are not cosmetic. The
 * boundaries decide whether a misconfigured host gets a loud refusal or a
 * silently degraded second factor -- a zero-digit or zero-period TOTP is not a
 * weaker second factor, it is no second factor at all.
 */

function boundaryTotp(int $period = 30, int $digits = 6, int $window = 1, ?ClockInterface $clock = null): TotpFactor
{
    return new TotpFactor(
        app(EnrollmentGuard::class),
        $clock ?? app(ClockInterface::class),
        'Vouch',
        $period,
        $digits,
        $window,
    );
}

function boundaryAttempt(int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => \Fissible\Vouch\Kernel\Attempt\AttemptState::FactorPending,
        'user_id' => $userId,
        'bound_context' => str_repeat('c', 64),
        'expires_at' => now()->addMinutes(10),
    ]);
}

it('accepts the smallest legal period and digits, and refuses one below', function (): void {
    /*
     * Both sides of each boundary. Asserting only the refusal would leave
     * `< 1` free to become `<= 1`, which refuses the smallest LEGAL value --
     * a config that should work would start throwing on boot.
     */
    expect(boundaryTotp(period: 1))->toBeInstanceOf(TotpFactor::class)
        ->and(boundaryTotp(digits: 1))->toBeInstanceOf(TotpFactor::class);

    expect(fn (): TotpFactor => boundaryTotp(period: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn (): TotpFactor => boundaryTotp(digits: 0))->toThrow(InvalidArgumentException::class);
});

it('accepts a zero drift window and refuses a negative one', function (): void {
    // Zero is legal and means "no drift tolerance"; negative is incoherent.
    expect(boundaryTotp(window: 0))->toBeInstanceOf(TotpFactor::class)
        ->and(fn (): TotpFactor => boundaryTotp(window: -1))->toThrow(InvalidArgumentException::class);
});

it('refuses an empty issuer', function (): void {
    // A set-but-blank VOUCH_TOTP_ISSUER= reads as "" rather than falling back.
    expect(fn (): TotpFactor => new TotpFactor(app(EnrollmentGuard::class), app(ClockInterface::class), ''))
        ->toThrow(InvalidArgumentException::class);
});

it('provisions with its documented defaults', function (): void {
    /*
     * The defaults are part of the package's contract -- a host that configures
     * nothing still gets a 30-second, 6-digit TOTP -- and nothing else asserts
     * them, so each could drift by one unnoticed.
     *
     * Asserted behaviourally, because the provisioning URI cannot carry it: an
     * authenticator app assumes 30 and 6, so otphp omits both parameters
     * whenever they hold their default values. A URI assertion would therefore
     * pass whatever the driver actually used.
     *
     * So a code is computed independently at period 30 / digits 6 and offered to
     * the driver. If either default drifted by one, the driver would be looking
     * at a different timestep or a different code width and reject it.
     *
     * Constructed with NO period, digits or window argument. Going through the
     * helper would pass 30 and 6 explicitly, so the constructor's own defaults
     * would never be read and could each drift by one with this test still
     * green -- which is exactly what the first version of it did.
     */
    $factor = new TotpFactor(app(EnrollmentGuard::class), app(ClockInterface::class));
    $uri = $factor->enroll(7, ['label' => 'ada@acme.example'])->secrets[0]->reveal();

    $secret = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;
    $timestamp = (new SystemClock())->now()->getTimestamp();

    // 60, not 0: the drift assertions below reach two timesteps into the past,
    // and a reference code at a negative timestamp is not a real instant.
    if (! is_string($secret) || $secret === '' || $timestamp < 60) {
        throw new RuntimeException('Enrollment produced no usable secret to compute a reference code from.');
    }

    $reference = TOTP::createFromSecret($secret, new SystemClock());
    $reference->setPeriod(30);
    $reference->setDigits(6);
    $code = $reference->at($timestamp);

    $result = $factor->verify(new VerificationRequest(boundaryAttempt(), ['code' => $code]));

    /*
     * The default window is pinned from both sides, because only the pair fixes
     * it at exactly one step: a code one step old must be accepted (a window of
     * 0 would reject it) and a code two steps old must not (a window of 2 would
     * accept it). Drift tolerance is a security parameter -- every extra step
     * widens the interval in which a shoulder-surfed code still works.
     */
    $oneStepOld = $factor->verify(new VerificationRequest(boundaryAttempt(), ['code' => $reference->at($timestamp - 30)]));
    $twoStepsOld = $factor->verify(new VerificationRequest(boundaryAttempt(), ['code' => $reference->at($timestamp - 60)]));

    expect($code)->toHaveLength(6)
        ->and($result->failure)->toBeNull()
        ->and($oneStepOld->failure)->toBeNull()
        ->and($twoStepsOld->failure)->toBe(FactorFailure::Mismatch)
        ->and($uri)->toContain('issuer=Vouch')
        ->and($uri)->toContain('ada%40acme.example');
});

it('refuses to enroll without a usable label', function (mixed $label): void {
    /*
     * The label is what the authenticator app shows next to the code. Enrolling
     * without one produces an entry the user cannot tell apart from any other.
     */
    $data = $label === '__absent__' ? [] : ['label' => $label];

    /*
     * The MESSAGE, not just the class. otphp's setLabel() also throws
     * InvalidArgumentException on an empty label, so asserting the class alone
     * passes with vouch's own guard removed -- the exception simply arrives from
     * a library call two lines later, after a TOTP secret has already been
     * generated. Pinning the wording is what makes this a test of the guard.
     */
    expect(fn () => boundaryTotp()->enroll(7, $data))
        ->toThrow(InvalidArgumentException::class, 'TotpFactor::enroll() requires a non-empty "label" string');
})->with(['absent' => ['__absent__'], 'empty' => [''], 'not a string' => [123]]);

it('does not replace when the caller says nothing about replacing', function (): void {
    /*
     * The default side of the replace contract. With `?? false` read as
     * `?? true`, an ordinary enrollment would silently disable the credential
     * the user is already authenticating with -- and every existing test would
     * stay green, because they all pass `replace` explicitly.
     */
    boundaryTotp()->enroll(7, ['label' => 'first']);
    $original = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;

    expect(fn () => boundaryTotp()->enroll(7, ['label' => 'second']))
        ->toThrow(\Fissible\Vouch\Enrollment\EnrollmentRefused::class);

    $active = AuthCredential::where('user_id', 7)->where('type', 'totp')->whereNull('disabled_at')->get();

    expect($active)->toHaveCount(1)
        ->and($active->first()?->secret)->toBe($original);
});

it('provisions at a non-default period and digit count', function (): void {
    /*
     * setPeriod() and setDigits() are invisible at the defaults, because 30 and
     * 6 are what the TOTP library would use anyway -- removing either call
     * changes nothing a default-configured test could see. Only a non-default
     * configuration makes those two calls load-bearing.
     */
    $factor = boundaryTotp(period: 60, digits: 8);
    $uri = $factor->enroll(7, ['label' => 'ada'])->secrets[0]->reveal();

    $secret = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;
    $timestamp = (new SystemClock())->now()->getTimestamp();

    if (! is_string($secret) || $secret === '' || $timestamp < 0) {
        throw new RuntimeException('Enrollment produced no usable secret.');
    }

    $reference = TOTP::createFromSecret($secret, new SystemClock());
    $reference->setPeriod(60);
    $reference->setDigits(8);
    $code = $reference->at($timestamp);

    $result = $factor->verify(new VerificationRequest(boundaryAttempt(), ['code' => $code]));

    /*
     * The URI assertions are the ones that kill setPeriod() and setDigits().
     * Neither call affects verification at all -- the period and digit count are
     * re-read from config on every verify(), and the credential stores only the
     * seed. What they affect is the provisioning URI, which is the ONLY place
     * the authenticator app learns how to generate codes. Drop either call and
     * the app is told 30/6 while the server checks 60/8: every code the user
     * ever produces is rejected, and no round-trip test written against the
     * server alone would notice.
     */
    expect($code)->toHaveLength(8)
        ->and($result->failure)->toBeNull()
        ->and($uri)->toContain('period=60')
        ->and($uri)->toContain('digits=8');
});

it('replaces an existing secret on an exact true', function (): void {
    boundaryTotp()->enroll(7, ['label' => 'first']);
    $original = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;

    boundaryTotp()->enroll(7, ['label' => 'second', 'replace' => true]);

    $active = AuthCredential::where('user_id', 7)->where('type', 'totp')->whereNull('disabled_at')->get();

    expect($active)->toHaveCount(1)
        ->and($active->first()?->secret)->not->toBe($original);
});

it('refuses rather than replacing when replace is merely truthy', function (mixed $replace): void {
    /*
     * `($data['replace'] ?? false) === true` is deliberately strict, and the
     * cardinality guard is what makes the strictness safe: a truthy string
     * arriving from a request body cannot silently disable the user's working
     * authenticator, because the enrollment is refused outright instead.
     *
     * The second assertion is the one that matters. A refusal that still
     * disabled the original credential would be a lockout with a polite error
     * message -- the user's authenticator gone and no replacement enrolled.
     */
    boundaryTotp()->enroll(7, ['label' => 'first']);
    $original = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;

    expect(fn () => boundaryTotp()->enroll(7, ['label' => 'second', 'replace' => $replace]))
        ->toThrow(\Fissible\Vouch\Enrollment\EnrollmentRefused::class);

    $active = AuthCredential::where('user_id', 7)->where('type', 'totp')->whereNull('disabled_at')->get();

    expect($active)->toHaveCount(1)
        ->and($active->first()?->secret)->toBe($original);
})->with(['truthy string' => ['yes'], 'integer one' => [1], 'string one' => ['1']]);

it('reports no credential rather than dereferencing a missing one', function (): void {
    /*
     * The null-safe read and the instanceof guard are the same control seen
     * twice. Without either, a verify() against a user who never enrolled is an
     * unhandled error on a public code path.
     */
    $result = boundaryTotp()->verify(new VerificationRequest(boundaryAttempt(), ['code' => '123456']));

    expect($result->failure)->toBe(FactorFailure::NoCredential);
});

it('reports no credential when the stored secret is blank', function (): void {
    /*
     * A blank secret verifies nothing, but it is not absent either -- without
     * the `$secret === ''` arm it reaches the TOTP library as a valid-looking
     * credential and the failure mode is whatever that library does with an
     * empty seed.
     */
    AuthCredential::create([
        'user_id' => 7,
        'type' => 'totp',
        'secret' => '',
        'strength' => 'possession',
    ]);

    $result = boundaryTotp()->verify(new VerificationRequest(boundaryAttempt(), ['code' => '123456']));

    expect($result->failure)->toBe(FactorFailure::NoCredential);
});

it('accepts a code newer than the recorded timestep', function (): void {
    /*
     * The complement to the replay tests, and the half that was missing.
     *
     * `last_used_timestep !== null && $matched <= $last_used` is an AND, and the
     * existing tests only ever exercise the case where BOTH sides are true. With
     * the AND read as an OR, any credential that has ever been used would refuse
     * every subsequent code as Consumed -- a permanent lockout for every user
     * who has successfully authenticated once, which is as total a failure as
     * this driver has and no test would have noticed.
     */
    $factor = boundaryTotp();
    $factor->enroll(7, ['label' => 'ada']);

    $credential = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail();
    $secret = $credential->secret;
    $timestamp = (new SystemClock())->now()->getTimestamp();

    if (! is_string($secret) || $secret === '' || $timestamp < 60) {
        throw new RuntimeException('Enrollment produced no usable secret.');
    }

    // A timestep genuinely in the past, so the current code is strictly newer.
    $credential->last_used_timestep = intdiv($timestamp, 30) - 1;
    $credential->save();

    $reference = TOTP::createFromSecret($secret, new SystemClock());
    $reference->setPeriod(30);
    $reference->setDigits(6);

    $result = $factor->verify(new VerificationRequest(boundaryAttempt(), ['code' => $reference->at($timestamp)]));

    expect($result->failure)->toBeNull();
});

it('skips timesteps before the epoch instead of computing a negative one', function (): void {
    /*
     * The `$step < 0` guard only ever fires within one drift window of the Unix
     * epoch, which is exactly why nothing else exercises it. A negative timestep
     * is not a real instant, and handing one to the TOTP library is undefined
     * behaviour rather than a mismatch.
     *
     * Verified at the epoch itself with a window wide enough that the loop
     * genuinely walks into negative steps.
     */
    $epoch = new class implements ClockInterface
    {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@0');
        }
    };

    $factor = boundaryTotp(window: 2, clock: $epoch);
    $factor->enroll(7, ['label' => 'ada']);

    $secret = AuthCredential::where('user_id', 7)->where('type', 'totp')->firstOrFail()->secret;

    if (! is_string($secret) || $secret === '') {
        throw new RuntimeException('Enrollment produced no usable secret.');
    }

    $reference = TOTP::createFromSecret($secret, new SystemClock());
    $reference->setPeriod(30);
    $reference->setDigits(6);

    $wrong = $factor->verify(new VerificationRequest(boundaryAttempt(), ['code' => '000000']));

    /*
     * Step zero is a REAL step and must still be compared. Asserting only the
     * mismatch above would leave `$step < 0` free to become `$step <= 0`, which
     * silently skips the current step -- at the epoch that is the whole
     * authentication, refused. The correct code for step 0 is the assertion that
     * separates "skipped the impossible steps" from "skipped one too many".
     */
    $right = $factor->verify(new VerificationRequest(boundaryAttempt(), ['code' => $reference->at(0)]));

    expect($wrong->failure)->toBe(FactorFailure::Mismatch)
        ->and($right->failure)->toBeNull();
});
