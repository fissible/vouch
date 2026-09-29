<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\Contracts\CaptchaVerifier;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Delivery\UnconfiguredCaptchaVerifier;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;

uses(RefreshDatabase::class);

/*
 * #82. The exemption and the report have to say the same thing.
 *
 * VouchServiceProvider::boot() refuses to boot on several misconfigurations, and
 * exempts vouch:doctor from each of them, on the reasoning that the command whose
 * job is to report a misconfiguration must not be stopped by one. Three of those
 * checks had no row in the report.
 *
 * So on a host with VOUCH_ATTEMPT_TTL=0, or no issuance-mutex secret, or a strict
 * assurance map naming an undeclared ability, `php artisan vouch:doctor` ran,
 * exited successfully, and listed nothing wrong -- while every login returned 500
 * or every issuance refused. The exemption delivered the operator to a command
 * that could not tell them what they had come to ask.
 *
 * Neither half is a regression on its own: the checks are recent and the command
 * was equally silent before they existed. What is wrong is the pair. An exemption
 * whose premise is "they can still diagnose it" has to be matched by something
 * that diagnoses it.
 *
 * The rows are named by the configuration key an operator has to change, because
 * that is what they will search for. The shipped rows name the thing to configure
 * too -- CaptchaVerifier is a binding rather than a key, which is why it keeps its
 * contract name.
 *
 * THE DRIFT THAT MATTERS is not a fifth exempt check appearing without a row -- it
 * is an existing check's PREDICATE changing while its row keeps the old one. Three
 * of the four share their predicate with boot already, through
 * IssuanceLockBucket::secret(), assertDeclared() and an instanceof. The attempt
 * window is the one the report re-implements, and measured, adding a single clause
 * to boot's version of it (`|| $ttl > 86400`) leaves every case below green while
 * VOUCH_ATTEMPT_TTL=90000 refuses boot for every command but this one and the
 * report calls that host healthy. That is #82 verbatim, reintroduced, with no new
 * exemption anywhere -- so counting exemptions in the provider's source would not
 * see it either, and such a census is coupled to how they are spelled: it fails
 * against a refactor collapsing them into one list, which is a plausible shape,
 * measured.
 *
 * So the guard below asserts the EQUIVALENCE instead of any spelling: for a range
 * of values, the report says missing exactly when boot refuses. It reads no source
 * and holds whatever either side is implemented as.
 *
 * What it does not cover, stated so the next reader knows: a fifth exempt check on
 * a setting outside its value set. Only a report that evaluates the same predicate
 * boot does closes both, which is why extracting the attempt window's predicate is
 * worth more than any test here.
 *
 * A row is present exactly when its check runs: the attempt window and the
 * issuance secret are checked unconditionally, so they are always reported, while
 * the CAPTCHA verifier and the strict-assurance map are checked only when their
 * feature is on and are reported only then. A row for a check that did not run
 * would be a claim about configuration nobody made.
 */

/**
 * Configure one doctor-exempt check so that boot would refuse it.
 *
 * Keyed by the row name, so a case cannot drift from the setting it configures.
 */
function refuseExemptCheck(string $prerequisite, bool $secondSpelling = false): void
{
    match ($prerequisite) {
        /*
         * Zero -- which is also what a set-but-blank VOUCH_ATTEMPT_TTL becomes -- or
         * the STRING "600". Both are refused at boot, and the second spelling is not
         * decoration: boot's condition is `! is_int($ttl) || $ttl < 1`, and zero fails
         * both halves at once, so a row that checked only positivity would report a
         * published config whose (int) cast was edited away as passing. That spelling
         * is what `vendor:publish --tag=vouch-config` hands an operator to edit.
         */
        'vouch.attempts.ttl_seconds' => Config::set('vouch.attempts.ttl_seconds', $secondSpelling ? '600' : 0),
        /*
         * Absent, or present and too short. IssuanceLockBucket::secret() has two
         * refusal branches and a row that only checked presence would call
         * VOUCH_ISSUANCE_LOCKS_SECRET=x a pass -- reachable straight from .env, since
         * that config entry is a bare env() with no cast and no default.
         */
        'vouch.issuance_locks.secret' => Config::set('vouch.issuance_locks.secret', $secondSpelling ? 'x' : null),
        'vouch.declared_abilities' => (function (): void {
            Config::set('vouch.assurance_strict', true);
            Config::set('vouch.declared_abilities', ['invoices.approve']);
            Config::set('vouch.assurance_requirements', ['invoices.aprove' => 'aal2']);
        })(),
        'CaptchaVerifier' => (function (): void {
            Config::set('vouch.throttle.captcha.enabled', true);
            Config::set('vouch.throttle.global.mode', 'enforce');
            Config::set('vouch.throttle.global.enforce_at', 5);
            Config::set('vouch.throttle.global.backoff_seconds', 1);
            app()->forgetInstance(ThrottleConfiguration::class);
            app()->instance(CaptchaVerifier::class, new UnconfiguredCaptchaVerifier());
        })(),
        default => throw new InvalidArgumentException('No refusing configuration for "' . $prerequisite . '".'),
    };
}

/**
 * Make every prerequisite OTHER than the exempt checks pass.
 *
 * Needed because the bare test environment already reports four missing
 * prerequisites, so the command already exits Failure there -- an exit-code
 * assertion made against it would hold for reasons that have nothing to do with
 * the row under test. Measured: the first version of the exit-code case below
 * passed against an implementation reporting no exempt rows at all.
 */
function healthyDoctorEnvironment(): void
{
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'doctor@example.test',
        'verified_at' => now(),
    ]);

    app()->instance(OtpDelivery::class, Mockery::mock(OtpDelivery::class));
    app()->instance(DeliveryEconomics::class, Mockery::mock(DeliveryEconomics::class));
}

/* ---- what the report says when nothing is wrong ----------------------- */

it('reports a row for each boot check it is exempt from', function (): void {
    $rows = doctorRows();

    /*
     * Present and passing. The test environment supplies both -- a 600 second
     * window and a 64 byte secret -- so these rows are the shape an operator sees
     * on a working host, and their presence is what makes the failing cases below
     * a change of status rather than the appearance of a row.
     */
    expect($rows)->toHaveKey('vouch.attempts.ttl_seconds');
    expect($rows['vouch.attempts.ttl_seconds']['status'] ?? null)->toBe('pass');
    expect($rows)->toHaveKey('vouch.issuance_locks.secret');
    expect($rows['vouch.issuance_locks.secret']['status'] ?? null)->toBe('pass');

    /*
     * And absent when their check does not run. Reporting "pass" for a CAPTCHA
     * verifier nobody enabled, or a strict map nobody turned on, would tell an
     * operator their configuration was checked when it was not.
     */
    /*
     * The shipped rows keep their positions. Two tests in VouchDoctorCommandTest
     * index into this list -- [0] and [2] -- so prepending the new rows instead of
     * appending them breaks them with nothing but "two arrays are identical" to go
     * on. Stated here, where the row set is specified, rather than left to be
     * rediscovered from that message.
     */
    expect(array_slice(array_keys($rows), 0, 4))
        ->toBe(['verified_at', 'OtpDelivery', 'durable_queue', 'DeliveryEconomics']);

    expect($rows)->not->toHaveKey('CaptchaVerifier');
    expect($rows)->not->toHaveKey('vouch.declared_abilities');
});

/* ---- and when it is ---------------------------------------------------- */

it('marks an exempt check missing when boot would refuse it', function (string $prerequisite, bool $reportedWhenHealthy): void {
    /*
     * The premise, stated per case rather than uniformly, because the two are
     * different claims. The unconditional checks start REPORTED AND PASSING, so the
     * assertion below is a change of status. The feature-gated ones start ABSENT,
     * and `expect(null)->not->toBe('missing')` would hold trivially -- saying so
     * rather than letting one line stand in for both.
     */
    expect(doctorStatus($prerequisite))->toBe($reportedWhenHealthy ? 'pass' : null);

    refuseExemptCheck($prerequisite);

    expect(doctorStatus($prerequisite))->toBe('missing');
})->with([
    'the attempt window' => ['vouch.attempts.ttl_seconds', true],
    'the issuance mutex secret' => ['vouch.issuance_locks.secret', true],
    'the strict assurance map' => ['vouch.declared_abilities', false],
    // Already reported before #82, and included so the set is the whole exemption
    // list rather than only the parts that were missing.
    'the CAPTCHA verifier' => ['CaptchaVerifier', false],
]);

it('marks an exempt check missing on every spelling boot refuses', function (string $prerequisite): void {
    /*
     * The second refusing spelling for the two checks whose boot condition is a
     * conjunction. Measured, each is a live hole on its own: a secret check without
     * the length floor, and a window check without the type half, each passed every
     * test in this file while boot refused the host.
     */
    expect(doctorStatus($prerequisite))->toBe('pass');

    refuseExemptCheck($prerequisite, secondSpelling: true);

    expect(doctorStatus($prerequisite))->toBe('missing');
})->with([
    'a secret too short to be one' => ['vouch.issuance_locks.secret'],
    'a window that is not an integer' => ['vouch.attempts.ttl_seconds'],
]);

it('fails its own exit code on an exempt check it reports missing', function (string $prerequisite): void {
    /*
     * Reporting is not enough on its own. An operator runs this in a script, and a
     * row buried in a passing report is a row nobody reads -- the command already
     * exits Failure when a prerequisite is missing, and these must count.
     */
    healthyDoctorEnvironment();

    /*
     * The control, and it is what makes the assertion below mean anything: the
     * command must be SUCCEEDING first. Without it this passes on the bare test
     * environment, which already reports four missing prerequisites and already
     * exits Failure -- measured, it did.
     */
    expect(Artisan::call('vouch:doctor', ['--json' => true]))->toBe(CommandExit::Success->value);

    refuseExemptCheck($prerequisite);

    expect(Artisan::call('vouch:doctor', ['--json' => true]))->toBe(CommandExit::Failure->value);

    // Exactly one, not merely non-zero: a row that also flipped something else
    // would still fail the exit code while misdescribing the host.
    expect(doctorMissingCount())->toBe(1);
})->with([
    'the attempt window' => ['vouch.attempts.ttl_seconds'],
    'the issuance mutex secret' => ['vouch.issuance_locks.secret'],
    'the strict assurance map' => ['vouch.declared_abilities'],
]);

/* ---- the exemption is still only for the doctor ------------------------ */

it('still refuses boot for a command that is not the doctor', function (string $prerequisite, string $expected): void {
    refuseExemptCheck($prerequisite);

    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:other'];

        /*
         * The message, not merely "something was thrown". The existing guard on the
         * CAPTCHA exemption asserted `not->toThrow(Throwable::class)`, which proves
         * nothing either way: Throwable is an interface, so Pest treats the argument
         * as a message substring, and with `not` the assertion passes whether an
         * exception was thrown or not.
         */
        expect(static fn (): null => (new VouchServiceProvider(app()))->boot())
            ->toThrow(RuntimeException::class, $expected);
    } finally {
        if ($original === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $original;
        }
    }
})->with([
    'the issuance mutex secret' => ['vouch.issuance_locks.secret', 'vouch.issuance_locks.secret'],
    'the strict assurance map' => ['vouch.declared_abilities', 'does not declare mapped abilities'],
    'the CAPTCHA verifier' => ['CaptchaVerifier', 'CAPTCHA escalation is enabled'],
]);

it('still refuses boot for a command that is not the doctor on an unusable attempt window', function (): void {
    // Separate because this one throws InvalidArgumentException, not RuntimeException,
    // and the type is part of what #55 pinned.
    refuseExemptCheck('vouch.attempts.ttl_seconds');

    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:other'];

        expect(static fn (): null => (new VouchServiceProvider(app()))->boot())
            ->toThrow(
                InvalidArgumentException::class,
                'Configuration "vouch.attempts.ttl_seconds" must be a positive integer; got 0.',
            );
    } finally {
        if ($original === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $original;
        }
    }
});

it('boots the doctor itself on a configuration that refuses every other command', function (): void {
    /*
     * The other half of the pair, and the one the reporting cases cannot show. They
     * run under pest's own argv, so boot was never actually exempted in those
     * processes -- they prove the report, not that the command survives the
     * configuration it is reporting on.
     *
     * The issuance secret specifically, because it is the one exempt check whose
     * positive half had no assertion anywhere: the attempt window, the CAPTCHA
     * verifier and the strict map each have one, and IssuanceLockCapacityTest says
     * in prose that this exemption exists without ever exercising it.
     */
    Config::set('vouch.issuance_locks.secret', null);

    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:doctor'];

        // Called directly: an exception here fails the test. The assertion after it
        // is what proves boot ran to completion rather than merely not throwing
        // something with a particular message.
        (new VouchServiceProvider(app()))->boot();

        expect(doctorStatus('vouch.issuance_locks.secret'))->toBe('missing');

        /*
         * And the control on the exemption itself: the identical configuration under
         * any other command must still refuse. Without it, deleting the boot check
         * would satisfy everything above.
         */
        $_SERVER['argv'] = ['artisan', 'vouch:other'];

        expect(static fn (): null => (new VouchServiceProvider(app()))->boot())
            ->toThrow(RuntimeException::class, 'vouch.issuance_locks.secret');
    } finally {
        if ($original === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $original;
        }
    }
});

/**
 * Whether provider boot refuses the current configuration for an ordinary command.
 *
 * Under `vouch:other` argv, so the exemption is not in play: this is the question
 * the report has to agree with.
 */
function bootRefusesHere(): bool
{
    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:other'];

        (new VouchServiceProvider(app()))->boot();

        return false;
    } catch (Throwable) {
        return true;
    } finally {
        if ($original === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $original;
        }
    }
}

it('reports the attempt window missing exactly when boot refuses it', function (mixed $value): void {
    /*
     * The one exempt check whose predicate the report re-implements, so the one place
     * the two can disagree without anybody adding an exemption. Asserted as an
     * equivalence over a range of values rather than as two separate truths, because
     * what went wrong in #82 -- and what a tightened predicate would repeat -- is the
     * two sides disagreeing, not either being wrong in isolation.
     *
     * 86400 and 90000 are here for that reason and no other: both are accepted today,
     * so both are `pass` on either side, and a bound introduced at boot on one of them
     * shows up as a disagreement immediately.
     *
     * This assertion alone would be satisfied by two sides that are wrong in the SAME
     * way -- it says they agree, not that they are right. The cases above are what
     * pin the values each must refuse.
     */
    Config::set('vouch.attempts.ttl_seconds', $value);

    expect(doctorStatus('vouch.attempts.ttl_seconds') === 'missing')->toBe(bootRefusesHere());
})->with([
    'zero' => [0],
    'a negative' => [-1],
    'a numeric string' => ['600'],
    'null' => [null],
    'the shipped default' => [600],
    'the smallest usable window' => [1],
    'a day' => [86400],
    'longer than a day' => [90000],
]);
