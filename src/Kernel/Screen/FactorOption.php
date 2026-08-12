<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

use Fissible\Vouch\Kernel\Factor\FactorStrength;

final readonly class FactorOption
{
    public function __construct(
        public string $factorId,
        public string $label,
        public FactorStrength $strength,
        public bool $isDefault,
    ) {}
}
