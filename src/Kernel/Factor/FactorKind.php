<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Factor;

enum FactorKind: string
{
    case Knowledge = 'knowledge';
    case Possession = 'possession';
    case Inherence = 'inherence';
}
