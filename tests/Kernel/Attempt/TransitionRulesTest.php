<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Kernel\Attempt\TransitionRules;

it('walks the happy path', function (): void {
    $rules = new TransitionRules();

    expect($rules->allows(AttemptState::Initiated, AttemptState::Identified))->toBeTrue()
        ->and($rules->allows(AttemptState::Identified, AttemptState::FactorPending))->toBeTrue()
        ->and($rules->allows(AttemptState::FactorPending, AttemptState::FactorSatisfied))->toBeTrue()
        ->and($rules->allows(AttemptState::FactorSatisfied, AttemptState::Authenticated))->toBeTrue();
});

it('allows another factor round after one is satisfied', function (): void {
    expect((new TransitionRules())->allows(AttemptState::FactorSatisfied, AttemptState::FactorPending))
        ->toBeTrue();
});

it('routes an unknown identifier to registration', function (): void {
    expect((new TransitionRules())->allows(AttemptState::Identified, AttemptState::RegistrationRequired))
        ->toBeTrue();
});

it('never authenticates straight from initiated', function (): void {
    expect((new TransitionRules())->allows(AttemptState::Initiated, AttemptState::Authenticated))
        ->toBeFalse();
});

it('never authenticates without a satisfied factor', function (): void {
    expect((new TransitionRules())->allows(AttemptState::Identified, AttemptState::Authenticated))
        ->toBeFalse()
        ->and((new TransitionRules())->allows(AttemptState::FactorPending, AttemptState::Authenticated))
        ->toBeFalse();
});

it('treats terminal states as terminal', function (): void {
    $rules = new TransitionRules();

    foreach ([AttemptState::Authenticated, AttemptState::Failed, AttemptState::Locked, AttemptState::RegistrationRequired] as $terminal) {
        expect($rules->isTerminal($terminal))->toBeTrue();

        foreach (AttemptState::cases() as $target) {
            expect($rules->allows($terminal, $target))->toBeFalse();
        }
    }
});

it('can fail or lock from any live state', function (): void {
    $rules = new TransitionRules();

    foreach ([AttemptState::Initiated, AttemptState::Identified, AttemptState::FactorPending, AttemptState::FactorSatisfied] as $live) {
        expect($rules->allows($live, AttemptState::Failed))->toBeTrue()
            ->and($rules->allows($live, AttemptState::Locked))->toBeTrue();
    }
});

it('never allows a state to transition to itself', function (): void {
    $rules = new TransitionRules();

    foreach (AttemptState::cases() as $state) {
        expect($rules->allows($state, $state))->toBeFalse();
    }
});
