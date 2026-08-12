<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use InvalidArgumentException;

final readonly class AnyOf implements Requirement
{
    /**
     * @param non-empty-list<Requirement> $requirements
     */
    public function __construct(public array $requirements)
    {
        // "Any of nothing" cannot be satisfied, but an empty branch is a config
        // mistake rather than a deliberately unsatisfiable policy, and it should say
        // so at construction instead of failing silently at evaluation.
        // @phpstan-ignore identical.alwaysFalse (guarding a PHPDoc-only invariant)
        if ($requirements === []) {
            throw new InvalidArgumentException('An any_of node must declare at least one requirement.');
        }
    }
}
