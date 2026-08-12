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
