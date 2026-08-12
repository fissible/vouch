<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Policy\AnyOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;

it('rejects an empty branch list', function (): void {
    // The runtime guard is the point: it protects the callers static analysis
    // cannot see, such as config-driven construction in Phase 2.
    // @phpstan-ignore argument.type
    expect(fn (): AnyOf => new AnyOf([]))
        ->toThrow(InvalidArgumentException::class, 'An any_of node must declare at least one requirement.');
});

it('accepts a single branch', function (): void {
    $node = new AnyOf([new FactorRequirement('passkey')]);

    expect($node->requirements)->toHaveCount(1);
});
