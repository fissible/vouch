<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

final readonly class AllOf implements Requirement
{
    /**
     * @param non-empty-list<Requirement> $requirements
     */
    public function __construct(
        public array $requirements,
        public bool $requireDistinctCredentials = true,
        public bool $requireIndependentAuthenticators = false,
    ) {}
}
