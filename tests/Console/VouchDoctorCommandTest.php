<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\VouchServiceProvider;
use Fissible\Vouch\Contracts\CaptchaVerifier;
use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Notifications\OtpQueueDispatcher;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Contracts\Queue\Factory as QueueFactory;
use Illuminate\Queue\SyncQueue;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Config;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('reports all adoption prerequisites without accepting subject input', function (): void {
    Config::set('vouch.throttle.captcha.enabled', true);
    Config::set('vouch.throttle.global.mode', 'enforce');
    Config::set('vouch.throttle.global.enforce_at', 5);
    Config::set('vouch.throttle.global.backoff_seconds', 1);
    app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'doctor@example.test',
        'verified_at' => null,
    ]);

    try {
        $exit = Artisan::call('vouch:doctor', ['--json' => true]);
        $report = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($report)) {
            throw new RuntimeException('Expected a doctor report object.');
        }

        $prerequisites = $report['prerequisites'] ?? null;

        if (! is_array($prerequisites)) {
            throw new RuntimeException('Expected doctor prerequisite rows.');
        }

        expect($exit)->toBe(CommandExit::Failure->value)
            /*
             * Seven, not five: #82 added rows for the boot checks this command is
             * exempt from, so that an exemption whose premise is "the operator can
             * still diagnose it" is matched by something that diagnoses it.
             */
            ->and($prerequisites)->toHaveCount(7)
            ->and($report['missing'])->toBe(4)
            ->and($prerequisites[0])->toBe([
                'prerequisite' => 'verified_at',
                'status' => 'missing',
                'total_identifiers' => 1,
                'verified_identifiers' => 0,
            ])
            ->and(array_keys(Artisan::all()['vouch:doctor']->getDefinition()->getArguments()))->toBe(['command'])
            ->and(array_keys(Artisan::all()['vouch:doctor']->getDefinition()->getOptions()))->toBe(['json', 'help', 'silent', 'quiet', 'verbose', 'version', 'ansi', 'no-interaction', 'env']);
    } finally {
        Config::set('vouch.throttle.captcha.enabled', false);
        Config::set('vouch.throttle.global.mode', 'observe');
        Config::set('vouch.throttle.global.enforce_at', null);
        Config::set('vouch.throttle.global.backoff_seconds', null);
        app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);
    }
});

it('returns success when every configured prerequisite passes', function (): void {
    Config::set('vouch.throttle.captcha.enabled', true);
    Config::set('vouch.throttle.global.mode', 'enforce');
    Config::set('vouch.throttle.global.enforce_at', 5);
    Config::set('vouch.throttle.global.backoff_seconds', 1);
    app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'doctor@example.test',
        'verified_at' => now(),
    ]);

    app()->instance(OtpDelivery::class, Mockery::mock(OtpDelivery::class));
    app()->instance(DeliveryEconomics::class, Mockery::mock(DeliveryEconomics::class));
    app()->instance(CaptchaVerifier::class, Mockery::mock(CaptchaVerifier::class));
    try {
        $exit = Artisan::call('vouch:doctor', ['--json' => true]);
        $report = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($report)) {
            throw new RuntimeException('Expected a doctor report object.');
        }

        expect($exit)->toBe(CommandExit::Success->value)
            ->and($report['missing'])->toBe(0);
    } finally {
        Config::set('vouch.throttle.captcha.enabled', false);
        Config::set('vouch.throttle.global.mode', 'observe');
        Config::set('vouch.throttle.global.enforce_at', null);
        Config::set('vouch.throttle.global.backoff_seconds', null);
        app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);
    }
});

it('exempts only vouch:doctor from the CAPTCHA boot guard', function (): void {
    Config::set('vouch.throttle.captcha.enabled', true);
    Config::set('vouch.throttle.global.mode', 'enforce');
    Config::set('vouch.throttle.global.enforce_at', 5);
    Config::set('vouch.throttle.global.backoff_seconds', 1);
    app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);
    app()->instance(\Fissible\Vouch\Contracts\CaptchaVerifier::class, new \Fissible\Vouch\Delivery\UnconfiguredCaptchaVerifier());
    $originalArgv = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:other'];
        expect(fn () => (new VouchServiceProvider(app()))->boot())
            ->toThrow('CAPTCHA escalation is enabled');

        /*
         * Called directly, and followed by a POSITIVE assertion. This previously read
         * `expect(...)->not->toThrow(\Throwable::class)`, which proves nothing either
         * way: Throwable is an interface, so Pest treats the argument as a message
         * substring, and with `not` the assertion passes whether an exception was
         * thrown or not. An exception here now fails the test by itself, and the
         * report below shows boot ran to completion.
         */
        $_SERVER['argv'] = ['artisan', 'vouch:doctor'];
        (new VouchServiceProvider(app()))->boot();

        // And the exemption leaves something to read: the report names the very
        // check boot skipped, rather than passing the host silently.
        expect(doctorStatus('CaptchaVerifier'))->toBe('missing');

        $_SERVER['argv'] = 'not-an-argument-vector';
        expect(fn () => (new VouchServiceProvider(app()))->boot())
            ->toThrow('CAPTCHA escalation is enabled');
    } finally {
        if ($originalArgv === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $originalArgv;
        }

        Config::set('vouch.throttle.captcha.enabled', false);
        Config::set('vouch.throttle.global.mode', 'observe');
        Config::set('vouch.throttle.global.enforce_at', null);
        Config::set('vouch.throttle.global.backoff_seconds', null);
        app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);
    }
});

it('renders the human-readable prerequisite table', function (): void {
    $exit = Artisan::call('vouch:doctor');
    $output = Artisan::output();

    expect($exit)->toBe(CommandExit::Failure->value)
        ->and($output)
        ->toContain('Prerequisite')
        ->toContain('Status')
        ->toContain('Details')
        ->toContain('verified_at')
        ->toContain('OtpDelivery')
        ->toContain('durable_queue')
        ->toContain('DeliveryEconomics')
        /*
         * The rows #82 added, in the TABLE and not only in --json. The table is what
         * a bare `php artisan vouch:doctor` prints, so a report that named these only
         * in the machine-readable form would still leave the operator reading the
         * output they actually get with nothing about the setting that is broken.
         */
        ->toContain('vouch.attempts.ttl_seconds')
        ->toContain('vouch.issuance_locks.secret')
        ->not()->toContain('{"missing"');
});

it('returns literal exit 2 and reports an unguarded prerequisite failure', function (): void {
    app()->bind(OtpDelivery::class, fn (): never => throw new RuntimeException('doctor delivery boom'));

    expect(Artisan::call('vouch:doctor', ['--json' => true]))->toBe(2)
        ->and(Artisan::output())->toContain('Vouch doctor could not complete: doctor delivery boom');
});

it('marks a guarded queue check missing without triggering diagnostic failure', function (): void {
    app()->instance(OtpQueueDispatcher::class, new OtpQueueDispatcher(
        new class implements QueueFactory {
            public function connection($connection = null): \Illuminate\Contracts\Queue\Queue
            {
                // SyncQueue's only constructor argument is
                // $dispatchAfterCommit. Passing the container here dated from
                // an older signature and made it truthy by accident; the
                // dispatcher only cares that the connection IS a SyncQueue.
                return new SyncQueue;
            }
        },
        app(DatabaseTime::class),
        'sync',
        'default',
    ));

    try {
        $exit = Artisan::call('vouch:doctor', ['--json' => true]);
        $report = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

        if (! is_array($report)) {
            throw new RuntimeException('Expected a doctor report object.');
        }

        $prerequisites = $report['prerequisites'] ?? null;

        if (! is_array($prerequisites)) {
            throw new RuntimeException('Expected doctor prerequisite rows.');
        }

        expect($exit)->toBe(CommandExit::Failure->value)
            ->and($prerequisites[2])
            ->toBe(['prerequisite' => 'durable_queue', 'status' => 'missing']);
    } finally {
        app()->forgetInstance(OtpQueueDispatcher::class);
    }
});

/*
 * #94. A prerequisite row must say what the operator has to change, and a check that
 * could not RUN has nothing to say about that.
 *
 * declaredAbilitiesStatus() caught Throwable around three separate things: resolving
 * AssuranceRequirements from the container, building the declared list from
 * vouch.declared_abilities, and comparing the two. Only the comparison refusing is a
 * finding about vouch.declared_abilities. The other two failing mean the check could
 * not look, and reporting them as `vouch.declared_abilities: missing` sends an
 * operator to add an ability when their requirements map is the thing that is broken
 * -- while suppressing the exit-2 diagnostic failure a command that cannot complete
 * is supposed to produce.
 *
 * The command already has the vocabulary: handle()'s outer catch reports a diagnostic
 * that could not finish and exits 2, and the report distinguishes that from a
 * prerequisite genuinely missing. The local catch erased the distinction for one row.
 *
 * Each case below is pinned by EXIT CODE as well as by row, because the two failure
 * modes are only distinguishable that way: a `missing` row exits 1, and both of these
 * were exiting 1 while printing a row about the wrong key.
 */

/**
 * Strict assurance on, with the two maps the declared-abilities row compares.
 *
 * Every OTHER prerequisite is made to pass as well, which is not tidiness. The default
 * test environment reports three missing on its own, so an exit code of 1 and a count
 * of 3 hold whether or not this row is the one at fault -- measured, the first version
 * of the finding case below asserted a count of 1 against an environment that reported
 * 3 and failed for a reason that had nothing to do with #94. With the rest passing,
 * the exit code and the count describe this row and nothing else.
 */
function doctorStrictRequirements(mixed $requirements, mixed $declared): void
{
    Config::set('vouch.assurance_strict', true);
    Config::set('vouch.assurance_requirements', $requirements);
    Config::set('vouch.declared_abilities', $declared);

    Config::set('vouch.throttle.captcha.enabled', true);
    Config::set('vouch.throttle.global.mode', 'enforce');
    Config::set('vouch.throttle.global.enforce_at', 5);
    Config::set('vouch.throttle.global.backoff_seconds', 1);
    app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);

    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'doctor-94@example.test',
        'verified_at' => now(),
    ]);

    app()->instance(OtpDelivery::class, Mockery::mock(OtpDelivery::class));
    app()->instance(DeliveryEconomics::class, Mockery::mock(DeliveryEconomics::class));
    app()->instance(CaptchaVerifier::class, Mockery::mock(CaptchaVerifier::class));
}

it('reports a diagnostic failure when the assurance requirements cannot be resolved', function (Closure $failure): void {
    doctorStrictRequirements(['invoices.approve' => 'aal2'], ['invoices.approve']);

    /*
     * TWO exception types, because the distinction the fix must make is about the
     * STAGE that failed and not about the class it failed with. Measured: with only
     * BindingResolutionException here, narrowing the command's local catch from
     * Throwable to RuntimeException passed every case in both files while a binding
     * that throws RuntimeException still produced exit 1 and the misleading
     * `vouch.declared_abilities: missing` row -- #94 intact behind a fix that looked
     * like one. The command's own docblock already gives the reason to catch
     * Throwable rather than a declared type; this is what holds it to that.
     *
     * Declarations are VALID in both rows, so a `missing` row could only come from the
     * resolution failure rather than from anything wrong with the declared list.
     */
    app()->bind(\Fissible\Vouch\Authorization\AssuranceRequirements::class, $failure);

    $exit = Artisan::call('vouch:doctor', ['--json' => true]);
    $output = Artisan::output();

    expect($exit)->toBe(2);
    // The real cause, not a row about a key the operator should not touch.
    expect($output)->toContain('requirements binding boom');
    expect($output)->not->toContain('vouch.declared_abilities');
    /*
     * And no report at all, which is the whitespace-independent way to say it. An
     * earlier version excluded a compact JSON fragment; measured, an implementation
     * that exits 2 AND prints the misleading row slipped through it as soon as the
     * JSON was pretty-printed, because the needle encoded the formatting rather than
     * the claim. A diagnostic that could not complete emits no prerequisite table.
     */
    expect($output)->not->toContain('prerequisites');
})->with([
    'a resolution failure' => [fn (): never => throw new \Illuminate\Contracts\Container\BindingResolutionException('requirements binding boom')],
    'a runtime failure inside the binding' => [fn (): never => throw new RuntimeException('requirements binding boom')],
]);

it('reports a diagnostic failure when the assurance requirements map is malformed', function (): void {
    // Valid declarations, invalid LEVEL on the requirements side. Measured, this
    // reported vouch.declared_abilities as missing -- a key that is correct here.
    doctorStrictRequirements(['invoices.approve' => 'typo-level'], ['invoices.approve']);

    $exit = Artisan::call('vouch:doctor', ['--json' => true]);
    $output = Artisan::output();

    expect($exit)->toBe(2);
    expect($output)->toContain('vouch.assurance_requirements');
    expect($output)->toContain('typo-level');
    // The key an operator must NOT be sent to, and no report to send them there with.
    expect($output)->not->toContain('vouch.declared_abilities');
    expect($output)->not->toContain('prerequisites');
});

it('reports a diagnostic failure when the declared abilities list is malformed', function (): void {
    /*
     * Beyond what #94 measured, and the same principle: a declared list that cannot be
     * BUILT is not a list missing an entry. "missing" tells an operator to add an
     * ability; the fix here is that the value is not a list of canonical strings at
     * all. The check could not complete, so it must say so.
     */
    doctorStrictRequirements(['invoices.approve' => 'aal2'], 'not-a-list');

    $exit = Artisan::call('vouch:doctor', ['--json' => true]);
    $output = Artisan::output();

    expect($exit)->toBe(2);
    expect($output)->toContain('vouch.declared_abilities');
    expect($output)->toContain('must be a list');
    /*
     * Here the key legitimately appears, in the construction error, so the bare
     * exclusion the other two cases use would be wrong. What must be absent is the
     * REPORT -- a row claiming the prerequisite was checked and found missing.
     */
    expect($output)->not->toContain('prerequisites');
});

it('reports a missing declaration as a prerequisite finding rather than a failure', function (): void {
    /*
     * The other half, and the half that must keep working: a requirements map that
     * builds fine and names an ability the declared list omits. That is a finding
     * about vouch.declared_abilities, it exits 1, and it is exactly what #82 added
     * this row for. A fix that moved the whole check out of the local catch would
     * turn this into exit 2 and lose the row.
     */
    doctorStrictRequirements(['invoices.approve' => 'aal2'], []);

    $exit = Artisan::call('vouch:doctor', ['--json' => true]);
    $output = Artisan::output();

    expect($exit)->toBe(CommandExit::Failure->value);
    expect($output)->toContain('"prerequisite":"vouch.declared_abilities","status":"missing"');
    // Exactly one, so the exit code and the count describe this row rather than the
    // three the default environment reports on its own.
    expect($output)->toContain('"missing":1');
});

it('reports a healthy strict assurance map as a passing prerequisite', function (): void {
    /*
     * The control the other three lacked. Nothing else in these console tests requires
     * a valid, fully declared strict map to report `pass`: measured, an implementation
     * that correctly propagates construction failures but then returns `missing` after
     * a SUCCESSFUL comparison passed both console files, 33 tests and 86 assertions,
     * because every case here either expected `missing` or expected exit 2.
     *
     * So the row is pinned in all three of its states -- pass, missing, and absent
     * because the check could not run -- rather than only the two that fail.
     */
    doctorStrictRequirements(['invoices.approve' => 'aal2'], ['invoices.approve', 'invoices.view']);

    $exit = Artisan::call('vouch:doctor', ['--json' => true]);
    $output = Artisan::output();

    expect($exit)->toBe(CommandExit::Success->value);
    /*
     * This also controls the exit-2 cases' exclusions: they assert 'prerequisites' is
     * ABSENT, which says nothing unless a report that did run contains it. Asserted
     * here, on the run that does.
     */
    expect($output)->toContain('prerequisites');
    expect($output)->toContain('"prerequisite":"vouch.declared_abilities","status":"pass"');
    // Nothing else missing either, so the exit code above is this row's to claim.
    expect($output)->toContain('"missing":0');
});
