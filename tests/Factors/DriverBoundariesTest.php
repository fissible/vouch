<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Factors\Drivers\EmailOtpFactor;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\LowerBoundRandomSource;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Psr\Clock\ClockInterface;

uses(RefreshDatabase::class);

/*
 * Group 1 of the Factors survivor audit for the three non-TOTP drivers: the
 * constructor boundaries, the enrollment guards, the assurance attributes, and
 * recovery-code normalisation and generation.
 *
 * On the assurance attributes, stated carefully. isMultiFactor, userVerified and
 * phishingResistant are hard-coded false because none of these credentials is
 * any of those things. As configured today this is future-proofing rather than a
 * live exposure: recovery evidence is filtered out of satisfiability by the
 * kernel, and the default assurance vocabulary caps at AAL2, so there is no
 * present default path by which these flags issue AAL3. The gap is that nothing
 * outside TOTP asserted them -- so the moment an AAL3 rung enters the vocabulary
 * or the recovery filter changes, an unasserted `false` becomes load-bearing with
 * no test behind it.
 */

function driverAttemptFor(int $userId = 7): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => AttemptState::FactorPending,
        'user_id' => $userId,
        'bound_context' => str_repeat('d', 64),
        'expires_at' => now()->addMinutes(10),
    ]);
}

function recoveryDriver(int $count = 10, int $length = 10): RecoveryCodeFactor
{
    return new RecoveryCodeFactor(app(EnrollmentGuard::class), app(ClockInterface::class), $count, $length);
}

function otpDriver(int $length = 6, int $ttlSeconds = 120): EmailOtpFactor
{
    return new EmailOtpFactor(
        app(EnrollmentGuard::class),
        app(ClockInterface::class),
        new ArrayOtpDelivery(),
        app(AuthThrottleStore::class),
        $length,
        $ttlSeconds,
    );
}

/**
 * Enrol an OTP credential and pull $times delivered codes off the wire.
 *
 * @return list<string>
 */
function otpCodesFrom(int $length, int $times): array
{
    $delivery = new ArrayOtpDelivery();
    $factor = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        app(ClockInterface::class),
        $delivery,
        app(AuthThrottleStore::class),
        $length,
        120,
    );

    $identifier = \Fissible\Vouch\Models\AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    $factor->enroll(7, ['identifier_id' => $identifier->id]);

    $codes = [];

    for ($i = 0; $i < $times; $i++) {
        $factor->challenge(new \Fissible\Vouch\Factors\ChallengeRequest(driverAttemptFor()));
        $codes[] = $delivery->lastCode();
    }

    return $codes;
}

it('refuses to enroll a password that is absent, blank or not a string', function (mixed $password): void {
    /*
     * The message, not just the class: without it the assertion would also be
     * satisfied by any InvalidArgumentException the hasher might raise further
     * down, which is the trap the TOTP label guard fell into.
     *
     * Enrolling '' would store a bcrypt digest of the empty string, and every
     * subsequent empty submission would verify against it.
     */
    $data = $password === '__absent__' ? [] : ['password' => $password];

    expect(fn () => app(PasswordFactor::class)->enroll(7, $data))
        ->toThrow(InvalidArgumentException::class, 'PasswordFactor::enroll() requires a non-empty "password" string');
})->with(['absent' => ['__absent__'], 'empty' => [''], 'not a string' => [123]]);

it('never reports aal3-eligible attributes for a recovery code', function (): void {
    $codes = recoveryDriver()->enroll(7, [])->secrets;
    $result = recoveryDriver()->verify(new VerificationRequest(driverAttemptFor(), ['code' => $codes[0]->reveal()]));

    $factor = $result->factor;

    expect($factor)->not->toBeNull()
        ->and($factor?->isMultiFactor)->toBeFalse()
        ->and($factor?->userVerified)->toBeFalse()
        ->and($factor?->phishingResistant)->toBeFalse();
});

it('accepts a recovery code however the user retypes it', function (string $submitted): void {
    /*
     * Recovery codes are read off paper and typed by hand, usually by someone
     * already locked out. Normalisation is the difference between a working
     * recovery path and a support ticket -- and strtoupper() specifically is
     * what makes a lowercase transcription work.
     */
    $code = recoveryDriver()->enroll(7, [])->secrets[0]->reveal();

    $variant = match ($submitted) {
        'lower' => strtolower($code),
        'spaced' => implode(' ', str_split($code, 4)),
        'hyphenated' => implode('-', str_split($code, 4)),
        default => $code,
    };

    $result = recoveryDriver()->verify(new VerificationRequest(driverAttemptFor(), ['code' => $variant]));

    expect($result->failure)->toBeNull();
})->with(['lower', 'spaced', 'hyphenated', 'verbatim']);

it('generates exactly the configured number of codes at the configured length', function (): void {
    /*
     * Deliberately more codes than the default, and longer. The generator draws
     * one character per iteration from `$alphabet[random_int(0, $max)]`, and
     * with `$max` off by one the draw runs past the end of the alphabet -- which
     * only shows up on the iterations that happen to hit it. Forty codes of
     * twelve characters is 480 draws, enough that a boundary error cannot hide
     * behind luck.
     */
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        recoveryDriver(count: 40, length: 12)->enroll(7, [])->secrets,
    );

    expect($codes)->toHaveCount(40);

    foreach ($codes as $code) {
        expect(strlen($code))->toBe(12)
            ->and($code)->toMatch('/^[A-Z0-9]+$/');
    }
});

it('refuses a recovery count or length below one, and accepts one', function (): void {
    expect(recoveryDriver(count: 1))->toBeInstanceOf(RecoveryCodeFactor::class)
        ->and(recoveryDriver(length: 1))->toBeInstanceOf(RecoveryCodeFactor::class)
        ->and(fn (): RecoveryCodeFactor => recoveryDriver(count: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn (): RecoveryCodeFactor => recoveryDriver(length: 0))->toThrow(InvalidArgumentException::class);
});

it('issues its documented default number of recovery codes at the default length', function (): void {
    // Built with no count or length argument, so the constructor's own defaults
    // are what gets read -- passing them explicitly would prove nothing.
    $codes = (new RecoveryCodeFactor(app(EnrollmentGuard::class), app(ClockInterface::class)))
        ->enroll(7, [])->secrets;

    expect($codes)->toHaveCount(10)
        ->and(strlen($codes[0]->reveal()))->toBe(10);
});

it('refuses an otp length or ttl below one, and accepts one', function (): void {
    /*
     * A zero-length OTP would deliver an empty code that any empty submission
     * matches; a zero ttl would expire every code before it could be typed.
     */
    expect(otpDriver(length: 1))->toBeInstanceOf(EmailOtpFactor::class)
        ->and(otpDriver(ttlSeconds: 1))->toBeInstanceOf(EmailOtpFactor::class)
        ->and(fn (): EmailOtpFactor => otpDriver(length: 0))->toThrow(InvalidArgumentException::class)
        ->and(fn (): EmailOtpFactor => otpDriver(ttlSeconds: 0))->toThrow(InvalidArgumentException::class);
});

it('draws recovery codes from the whole alphabet', function (): void {
    /*
     * Entropy, not formatting. The generator indexes a 32-character alphabet
     * with `random_int(0, strlen($alphabet) - 1)`, and both ends of that range
     * are load-bearing: off by one at the top and 'Z' is never drawn, off by one
     * at the bottom and '0' is never drawn. Either silently costs every code a
     * fraction of a bit, and no assertion about a code's length or shape can see
     * it.
     *
     * Asserting COVERAGE rather than distribution keeps this deterministic in
     * practice. Sixty codes of sixteen characters is 960 draws; the chance any
     * one of 32 characters is absent by luck is about 3e-10, while under either
     * mutation a specific character is absent every time.
     */
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        recoveryDriver(count: 60, length: 16)->enroll(7, [])->secrets,
    );

    $seen = count_chars(implode('', $codes), 3);

    // Crockford-style: no I, L, O or U, so they cannot be misread as 1, 0 or V.
    expect(str_split((string) $seen))->toEqualCanonicalizing(str_split('0123456789ABCDEFGHJKMNPQRSTVWXYZ'));
});

it('draws otp codes from every digit', function (): void {
    /*
     * The same boundary in the numeric generator: `random_int(0, 9)`. Off by one
     * at the bottom and no code ever contains a zero; off by one at the top and
     * the range goes negative, which puts a '-' in a code the user is asked to
     * type.
     */
    $joined = implode('', otpCodesFrom(length: 20, times: 30));

    expect($joined)->toMatch('/^[0-9]+$/')
        ->and(str_split((string) count_chars($joined, 3)))->toEqualCanonicalizing(str_split('0123456789'));
});

it('draws recovery characters from the first index of the alphabet', function (): void {
    /*
     * The boundary itself, made deterministic. The aggregate coverage test above
     * shows every character CAN appear; it cannot show which index the range
     * starts at, because a generator asking for `int(-1, $max)` still produces
     * perfectly ordinary-looking codes -- PHP reads $alphabet[-1] as the LAST
     * character, so the only symptom is a bias no sample can distinguish from
     * luck without a flaky distribution test.
     *
     * With a source that returns its own lower bound, the question becomes
     * exact: drawing from index 0 must yield '0', the first character of the
     * alphabet. Under the mutation it yields 'Z', every time.
     */
    $random = new LowerBoundRandomSource();

    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        (new RecoveryCodeFactor(app(EnrollmentGuard::class), app(ClockInterface::class), 3, 8, $random))
            ->enroll(7, [])->secrets,
    );

    // The range as well as the result: a generator that asked for int(1, $max)
    // would still be self-consistent, just permanently missing a character.
    $ranges = array_values(array_unique(array_map(
        static fn (array $call): string => $call['min'] . '..' . $call['max'],
        $random->calls,
    )));

    expect($codes)->toBe(['00000000', '00000000', '00000000'])
        ->and($ranges)->toBe(['0..31']);
});

it('draws otp digits from zero', function (): void {
    // The same boundary in the numeric generator. int(-1, 9) would put a '-' in
    // a code the user is asked to type; int(1, 9) would never produce a zero.
    $random = new LowerBoundRandomSource();

    $delivery = new ArrayOtpDelivery();
    $factor = new EmailOtpFactor(
        app(EnrollmentGuard::class),
        app(ClockInterface::class),
        $delivery,
        app(AuthThrottleStore::class),
        6,
        120,
        $random,
    );

    $identifier = \Fissible\Vouch\Models\AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    $factor->enroll(7, ['identifier_id' => $identifier->id]);
    $factor->challenge(new \Fissible\Vouch\Factors\ChallengeRequest(driverAttemptFor()));

    $ranges = array_values(array_unique(array_map(
        static fn (array $call): string => $call['min'] . '..' . $call['max'],
        $random->calls,
    )));

    expect($delivery->lastCode())->toBe('000000')
        ->and($ranges)->toBe(['0..9']);
});
