<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

it('carries everything an adapter needs to render', function (): void {
    $spec = new ScreenSpec(
        step: AuthStep::Challenge,
        offeredFactors: [
            new FactorOption('passkey', 'Use a passkey', FactorStrength::PossessionStrong, isDefault: true),
            new FactorOption('totp', 'Use an authenticator app', FactorStrength::Possession, isDefault: false),
        ],
        fields: [new FieldSpec('code', 'text', 'one-time-code', maxLength: 6)],
        challengePayload: ['delivery' => 'email'],
        errors: [],
        retry: new RetryPolicy(attemptsRemaining: 4, lockedUntil: null),
    );

    expect($spec->step)->toBe(AuthStep::Challenge)
        ->and($spec->offeredFactors)->toHaveCount(2)
        ->and($spec->offeredFactors[0]->isDefault)->toBeTrue()
        ->and($spec->fields[0]->autocomplete)->toBe('one-time-code')
        ->and($spec->fields[0]->maxLength)->toBe(6)
        ->and($spec->challengePayload)->toBe(['delivery' => 'email'])
        ->and($spec->retry?->attemptsRemaining)->toBe(4);
});

it('supports a screen with no challenge and no retry disclosure', function (): void {
    $spec = new ScreenSpec(
        step: AuthStep::Identify,
        offeredFactors: [],
        fields: [new FieldSpec('identifier', 'email', 'username', maxLength: null)],
        challengePayload: null,
        errors: ['Check your email.'],
        retry: null,
    );

    expect($spec->challengePayload)->toBeNull()
        ->and($spec->retry)->toBeNull()
        ->and($spec->errors)->toBe(['Check your email.']);
});
