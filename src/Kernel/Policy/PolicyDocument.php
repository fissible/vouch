<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;

final readonly class PolicyDocument
{
    public function __construct(
        public Requirement $requirement,
        public EnumerationPosture $posture,
    ) {}
}
