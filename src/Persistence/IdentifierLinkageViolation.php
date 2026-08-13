<?php

declare(strict_types=1);

namespace Fissible\Vouch\Persistence;

use InvalidArgumentException;

/**
 * A credential-to-identifier link broke one of Amendment A's three rules.
 *
 * None of these can be expressed as a foreign key: same-user relates two
 * independent FKs to each other, verified is a column value rather than a
 * reference, and immutability is a rule about updates rather than about rows.
 */
final class IdentifierLinkageViolation extends InvalidArgumentException
{
    public static function missing(int $identifierId): self
    {
        return new self(sprintf(
            'Identifier %d does not exist, so no credential may reference it.',
            $identifierId,
        ));
    }

    public static function crossUser(int $credentialUserId, int $identifierUserId): self
    {
        return new self(sprintf(
            'Refusing to link a credential owned by user %d to an identifier owned by user %d. '
            . 'An OTP credential delivers to its identifier, so a cross-user link routes '
            . 'authentication codes to somebody else.',
            $credentialUserId,
            $identifierUserId,
        ));
    }

    public static function unverified(int $identifierId): self
    {
        return new self(sprintf(
            'Identifier %d is not verified. An unverified identifier is attacker-supplied '
            . 'until proven, and linking OTP delivery to one routes codes to an address '
            . 'nobody has demonstrated control of.',
            $identifierId,
        ));
    }

    public static function frozen(int $identifierId): self
    {
        return new self(sprintf(
            'Identifier %d is referenced by at least one credential, so its value is frozen. '
            . 'Mutating it in place would silently redirect every OTP credential pointing at '
            . 'this row — an account takeover requiring no credential change at all. Create '
            . 'and verify a new identifier, then enroll a new credential against it.',
            $identifierId,
        ));
    }
}
