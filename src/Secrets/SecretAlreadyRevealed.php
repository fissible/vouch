<?php

declare(strict_types=1);

namespace Fissible\Vouch\Secrets;

use RuntimeException;

/**
 * A one-time secret was read twice.
 *
 * Failing loudly is the point. A second read means something kept a reference
 * to bearer material past the single moment it was meant to be displayed, and
 * the alternative — handing it over again — is the quiet leak this class
 * exists to prevent.
 */
final class SecretAlreadyRevealed extends RuntimeException
{
    public static function make(): self
    {
        return new self(
            'This secret has already been revealed and cannot be read again. '
            . 'Enrollment secrets are displayed exactly once; if you need it later, '
            . 'you need a new enrollment, not a second read.',
        );
    }
}
