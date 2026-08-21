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
        ->and($spec->offeredFactors)->toHaveCount(2);

    expect($spec->offeredFactors[0]->factorId)->toBe('passkey')
        ->and($spec->offeredFactors[0]->label)->toBe('Use a passkey')
        ->and($spec->offeredFactors[0]->strength)->toBe(FactorStrength::PossessionStrong)
        ->and($spec->offeredFactors[0]->isDefault)->toBeTrue();

    expect($spec->offeredFactors[1]->factorId)->toBe('totp')
        ->and($spec->offeredFactors[1]->label)->toBe('Use an authenticator app')
        ->and($spec->offeredFactors[1]->strength)->toBe(FactorStrength::Possession)
        ->and($spec->offeredFactors[1]->isDefault)->toBeFalse();

    expect($spec->fields[0]->name)->toBe('code')
        ->and($spec->fields[0]->type)->toBe('text')
        ->and($spec->fields[0]->autocomplete)->toBe('one-time-code')
        ->and($spec->fields[0]->maxLength)->toBe(6);

    expect($spec->challengePayload)->toBe(['delivery' => 'email'])
        ->and($spec->retry?->attemptsRemaining)->toBe(4)
        ->and($spec->retry?->lockedUntil)->toBeNull()
        ->and($spec->captchaRequired)->toBeNull();
});

it('carries a shared-volume CAPTCHA requirement explicitly', function (): void {
    $spec = new ScreenSpec(
        step: AuthStep::Challenge,
        offeredFactors: [],
        fields: [],
        challengePayload: null,
        errors: [],
        retry: null,
        captchaRequired: true,
    );

    expect($spec->captchaRequired)->toBeTrue();
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

    expect($spec->step)->toBe(AuthStep::Identify)
        ->and($spec->offeredFactors)->toHaveCount(0);

    expect($spec->fields[0]->name)->toBe('identifier')
        ->and($spec->fields[0]->type)->toBe('email')
        ->and($spec->fields[0]->autocomplete)->toBe('username')
        ->and($spec->fields[0]->maxLength)->toBeNull();

    expect($spec->challengePayload)->toBeNull()
        ->and($spec->retry)->toBeNull()
        ->and($spec->errors)->toBe(['Check your email.']);
});

it('discloses retry limits with lock expiry', function (): void {
    $lockedUntil = new DateTimeImmutable('2026-08-12T15:30:45Z');
    $retryAfter = new DateTimeImmutable('2026-08-12T15:15:30Z');
    $retry = new RetryPolicy(
        attemptsRemaining: 2,
        lockedUntil: $lockedUntil,
        retryAfter: $retryAfter,
    );

    expect($retry->attemptsRemaining)->toBe(2)
        ->and($retry->lockedUntil)->toBe($lockedUntil)
        ->and($retry->retryAfter)->toBe($retryAfter);
});

it('keeps the measured retry deadline optional for existing callers', function (): void {
    $retry = new RetryPolicy(attemptsRemaining: 2, lockedUntil: null);

    expect($retry->retryAfter)->toBeNull();
});
