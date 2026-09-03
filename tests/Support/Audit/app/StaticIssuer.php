<?php

declare(strict_types=1);

namespace Vendor\Probe;

/** A static mint, so a variable-class call to it is plausibly issuance. */
final class StaticIssuer
{
    public static function createToken(string $name): NewToken
    {
        return new NewToken();
    }
}
