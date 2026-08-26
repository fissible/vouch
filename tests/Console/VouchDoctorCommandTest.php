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
            ->and($prerequisites)->toHaveCount(5)
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
        expect(Artisan::call('vouch:doctor', ['--json' => true]))->toBe(CommandExit::Success->value)
            ->and(json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR)['missing'])
            ->toBe(0);
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

        $_SERVER['argv'] = ['artisan', 'vouch:doctor'];
        expect(fn () => (new VouchServiceProvider(app()))->boot())->not->toThrow(\Throwable::class);

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
        ->not->toContain('{"missing"');
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
                return new SyncQueue(app());
            }
        },
        app(DatabaseTime::class),
        'sync',
        'default',
    ));

    try {
        expect(Artisan::call('vouch:doctor', ['--json' => true]))->toBe(CommandExit::Failure->value)
            ->and(json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR)['prerequisites'][2])
            ->toBe(['prerequisite' => 'durable_queue', 'status' => 'missing']);
    } finally {
        app()->forgetInstance(OtpQueueDispatcher::class);
    }
});
