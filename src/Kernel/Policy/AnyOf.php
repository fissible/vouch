<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

final readonly class AnyOf implements Requirement
{
    /**
     * @param non-empty-list<Requirement> $requirements
     */
    public function __construct(public array $requirements) {}
}
