<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Enumeration;

enum EnumerationPosture: string
{
    case Friendly = 'friendly';
    case Strict = 'strict';

    public function isAtLeastAsStrictAs(self $other): bool
    {
        return $this === self::Strict || $other === self::Friendly;
    }
}
