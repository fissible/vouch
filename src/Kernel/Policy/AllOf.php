<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use InvalidArgumentException;

final readonly class AllOf implements Requirement
{
    /**
     * @param non-empty-list<Requirement> $requirements
     */
    public function __construct(
        public array $requirements,
        public bool $requireDistinctCredentials = true,
        public bool $requireIndependentAuthenticators = false,
    ) {
        // "All of nothing" is vacuously true, and a vacuously true policy is an
        // authentication bypass. The docblock alone does not stop it: the kernel is
        // public API and Phase 2 constructs these directly, not only via PolicyParser.
        // @phpstan-ignore identical.alwaysFalse (guarding a PHPDoc-only invariant)
        if ($requirements === []) {
            throw new InvalidArgumentException('An all_of node must declare at least one requirement.');
        }
    }
}
