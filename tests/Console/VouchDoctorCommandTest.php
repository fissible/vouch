<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\VouchServiceProvider;
use Fissible\Vouch\Models\AuthIdentifier;
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
