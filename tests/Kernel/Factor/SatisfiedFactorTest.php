<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;

it('records everything satisfiability needs', function (): void {
    $at = new DateTimeImmutable('2026-08-11T10:00:00+00:00');

    $factor = new SatisfiedFactor(
        factorId: 'passkey',
        credentialId: 'cred-1',
        kind: FactorKind::Possession,
        strength: FactorStrength::PossessionStrong,
        isMultiFactor: true,
        userVerified: true,
        phishingResistant: true,
        authenticatorId: 'auth-1',
        satisfiedAt: $at,
    );

    expect($factor->factorId)->toBe('passkey')
        ->and($factor->credentialId)->toBe('cred-1')
        ->and($factor->kind)->toBe(FactorKind::Possession)
        ->and($factor->strength)->toBe(FactorStrength::PossessionStrong)
        ->and($factor->isMultiFactor)->toBeTrue()
        ->and($factor->userVerified)->toBeTrue()
        ->and($factor->phishingResistant)->toBeTrue()
        ->and($factor->authenticatorId)->toBe('auth-1')
        ->and($factor->satisfiedAt)->toBe($at);
});

it('allows a null authenticator for factors with no device', function (): void {
    $factor = new SatisfiedFactor(
        factorId: 'password',
        credentialId: 'cred-2',
        kind: FactorKind::Knowledge,
        strength: FactorStrength::Knowledge,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable('2026-08-11T10:00:00+00:00'),
    );

    expect($factor->authenticatorId)->toBeNull();
});
