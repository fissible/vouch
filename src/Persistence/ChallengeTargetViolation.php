<?php

declare(strict_types=1);

namespace Fissible\Vouch\Persistence;

use InvalidArgumentException;

/**
 * A challenge named an unusable delivery target, or named none when one was required.
 *
 * The challenge row is the record of what was actually sent. If it can be
 * created without a valid target, verification has nothing authoritative to
 * compare against and the satisfied credential is reconstructed by guesswork.
 */
final class ChallengeTargetViolation extends InvalidArgumentException
{
    public static function targetRequired(string $factorType): self
    {
        return new self(sprintf(
            'A %s challenge must name the credential it was delivered against. Without one, '
            . 'the satisfied credential is chosen after the fact and kernel distinctness '
            . 'describes a delivery that never happened.',
            $factorType,
        ));
    }

    public static function decoyNamedTarget(int $credentialId): self
    {
        return new self(sprintf(
            'Decoy challenge cannot name credential %d. A decoy with a real target could '
            . 'contact a provider or satisfy verification while claiming to be inert.',
            $credentialId,
        ));
    }

    public static function missing(int $credentialId): self
    {
        return new self(sprintf('Credential %d does not exist.', $credentialId));
    }

    public static function disabled(int $credentialId): self
    {
        return new self(sprintf(
            'Credential %d is disabled and must not receive a challenge.',
            $credentialId,
        ));
    }

    public static function foreignUser(int $credentialId, ?int $attemptUserId): self
    {
        return new self(sprintf(
            'Credential %d does not belong to the attempt user (%s). A challenge delivered '
            . 'against another user credential would authenticate the wrong account.',
            $credentialId,
            $attemptUserId === null ? 'the attempt has no identified user' : (string) $attemptUserId,
        ));
    }

    public static function notIdentifierLinked(int $credentialId): self
    {
        return new self(sprintf(
            'Credential %d has no identifier, so there is nowhere to deliver a code.',
            $credentialId,
        ));
    }
}
