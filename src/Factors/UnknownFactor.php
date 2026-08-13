<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors;

use InvalidArgumentException;

final class UnknownFactor extends InvalidArgumentException
{
    /**
     * @param  list<string>  $known
     */
    public static function for(string $id, array $known): self
    {
        return new self(sprintf(
            'No factor driver is registered for "%s". Registered: %s.',
            $id,
            $known === [] ? 'none' : implode(', ', $known),
        ));
    }
}
