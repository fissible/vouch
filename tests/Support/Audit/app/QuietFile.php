<?php

declare(strict_types=1);

namespace Vendor\Probe;

/**
 * Nothing here issues anything.
 *
 * The docblock mentions createToken( deliberately: a scanner that matched text
 * rather than tokens would report this file, and a report that cries wolf on
 * prose is one an operator learns to ignore.
 */
final class QuietFile
{
    public function describe(): string
    {
        // Also createToken( in a comment, and below in a string.
        return 'call createToken( to mint a token';
    }
}
