<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Policy\AllOf;
use Fissible\Vouch\Kernel\Policy\FactorRequirement;

it('rejects an empty requirement list', function (): void {
    // Vacuous truth: an all_of with nothing in it is satisfied by nothing at all,
    // which is a logged-in session with no factors.
    // The runtime guard is the point: it protects the callers static analysis
    // cannot see, such as config-driven construction in Phase 2.
    // @phpstan-ignore argument.type
    expect(fn (): AllOf => new AllOf([]))
        ->toThrow(InvalidArgumentException::class, 'An all_of node must declare at least one requirement.');
});

it('accepts a single requirement', function (): void {
    $node = new AllOf([new FactorRequirement('password')]);

    expect($node->requirements)->toHaveCount(1);
});

it('requires distinct credentials and permits shared authenticators by default', function (): void {
    $node = new AllOf([new FactorRequirement('password')]);

    expect($node->requireDistinctCredentials)->toBeTrue()
        ->and($node->requireIndependentAuthenticators)->toBeFalse();
});
