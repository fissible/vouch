<?php

declare(strict_types=1);

namespace Fissible\Vouch\Persistence;

use InvalidArgumentException;

/**
 * A value exceeded a declared bound and was refused before persistence.
 *
 * Refusing rather than truncating is the whole point. Under a non-strict MySQL
 * `sql_mode` an over-length value is silently truncated, and two distinct
 * issuers or subjects truncating to the same string would collide in — or
 * wrongly match — the unique index on (connection_id, issuer, subject). That is
 * the cross-tenant identity guard of parent spec §7.2 defeated from the inside.
 * SQLite compounds it by not enforcing VARCHAR length at all, so the engine the
 * suite runs on by default is the one that would hide the bug.
 */
final class ValueBoundViolation extends InvalidArgumentException
{
    public static function tooLong(string $model, string $attribute, int $max, int $actual): self
    {
        return new self(sprintf(
            '%s::$%s exceeds its %d-character bound (%d given). Vouch refuses rather than '
            . 'truncates: a truncated identity value can collide with another under a unique index.',
            $model,
            $attribute,
            $max,
            $actual,
        ));
    }

    public static function notAscii(string $model, string $attribute): self
    {
        return new self(sprintf(
            '%s::$%s must be ASCII. Vouch refuses rather than normalises: two distinct '
            . 'values normalising to one would collide under a unique index.',
            $model,
            $attribute,
        ));
    }
}
