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
function refuseExemptCheck(string $prerequisite): void
{
    match ($prerequisite) {
        // Zero, which is also what a set-but-blank VOUCH_ATTEMPT_TTL becomes.
        'vouch.attempts.ttl_seconds' => Config::set('vouch.attempts.ttl_seconds', 0),
        // Absent rather than short: the package ships no default, so this is the
        // state a host that never set it is actually in.
        'vouch.issuance_locks.secret' => Config::set('vouch.issuance_locks.secret', null),
        'vouch.assurance_strict' => (function (): void {
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
    expect($rows)->not->toHaveKey('CaptchaVerifier');
    expect($rows)->not->toHaveKey('vouch.assurance_strict');
});

/* ---- and when it is ---------------------------------------------------- */

it('marks an exempt check missing when boot would refuse it', function (string $prerequisite): void {
    // The premise: this row is not already missing, so the change below is caused
    // by the configuration and not by the fixture's starting state.
    expect(doctorStatus($prerequisite))->not->toBe('missing');

    refuseExemptCheck($prerequisite);

    expect(doctorStatus($prerequisite))->toBe('missing');
})->with([
    'the attempt window' => ['vouch.attempts.ttl_seconds'],
    'the issuance mutex secret' => ['vouch.issuance_locks.secret'],
    'the strict assurance map' => ['vouch.assurance_strict'],
    // Already reported before #82, and included so the set is the whole exemption
    // list rather than only the parts that were missing.
    'the CAPTCHA verifier' => ['CaptchaVerifier'],
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
})->with([
    'the attempt window' => ['vouch.attempts.ttl_seconds'],
    'the issuance mutex secret' => ['vouch.issuance_locks.secret'],
    'the strict assurance map' => ['vouch.assurance_strict'],
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
    'the strict assurance map' => ['vouch.assurance_strict', 'does not declare mapped abilities'],
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
