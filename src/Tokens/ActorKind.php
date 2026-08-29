<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

enum ActorKind: string
{
    case Human = 'human';
    case Machine = 'machine';
}
