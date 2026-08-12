<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Factor\FactorStrength;

final readonly class FactorRequirement implements Requirement
{
    public function __construct(
        public string $factorId,
        public ?bool $userVerified = null,
        public ?FactorStrength $minimumStrength = null,
        public ?bool $phishingResistant = null,
    ) {}
}
