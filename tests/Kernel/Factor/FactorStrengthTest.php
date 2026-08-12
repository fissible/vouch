<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Factor\FactorStrength;

it('orders strengths from weakest to strongest', function (): void {
    expect(FactorStrength::PossessionStrong->atLeast(FactorStrength::Possession))->toBeTrue()
        ->and(FactorStrength::Possession->atLeast(FactorStrength::PossessionWeak))->toBeTrue()
        ->and(FactorStrength::PossessionWeak->atLeast(FactorStrength::Knowledge))->toBeTrue();
});

it('treats a strength as satisfying itself', function (): void {
    expect(FactorStrength::Possession->atLeast(FactorStrength::Possession))->toBeTrue();
});

it('rejects a weaker strength', function (): void {
    expect(FactorStrength::PossessionWeak->atLeast(FactorStrength::PossessionStrong))->toBeFalse();
});

it('ranks recovery below every real factor', function (): void {
    expect(FactorStrength::Recovery->atLeast(FactorStrength::Knowledge))->toBeFalse();
});

it('pins the backing values, which are a persisted contract', function (): void {
    // Mutation testing cannot reach these: an enum case declaration is not an
    // executable line, so a renumbering is invisible to coverage. Pin them by
    // hand — the ints are what gets stored and rehydrated with from().
    expect(FactorStrength::Recovery->value)->toBe(0)
        ->and(FactorStrength::Knowledge->value)->toBe(10)
        ->and(FactorStrength::PossessionWeak->value)->toBe(20)
        ->and(FactorStrength::Possession->value)->toBe(30)
        ->and(FactorStrength::PossessionStrong->value)->toBe(40);
});
