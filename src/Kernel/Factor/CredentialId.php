<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Factor;

use InvalidArgumentException;

/**
 * The identity shared by factor evidence and raw credential-lock requests.
 *
 * The schema is numeric, so accepting aliases such as `09` would let a proof
 * name a credential differently from the row it locks. SQLite and PostgreSQL
 * cap the portable domain at signed bigint even though MySQL uses unsigned.
 * Keep the bound as text: integer casts can saturate and floating-point
 * comparisons cannot distinguish adjacent identities near the maximum.
 */
final class CredentialId
{
    public static function validate(string $value): void
    {
        // Absolute anchors reject the final newline that PCRE's $ permits.
        if (preg_match('/\A[1-9][0-9]*\z/', $value) !== 1
            || strlen($value) > 19
            || (strlen($value) === 19 && strcmp($value, '9223372036854775807') > 0)) {
            throw new InvalidArgumentException(sprintf(
                'Credential id "%s" must be a canonical positive decimal string no greater than 9223372036854775807.',
                $value,
            ));
        }
    }
}
