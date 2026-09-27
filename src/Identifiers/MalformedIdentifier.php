<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

use InvalidArgumentException;

/**
 * A submitted identifier was not a value that can name anybody, and was refused.
 *
 * REFUSED RATHER THAN REPAIRED, for the reason `ValueBoundViolation` records
 * about truncation: stripping the offending byte is precisely how an
 * attacker-chosen string becomes somebody else's identifier. PostgreSQL
 * truncates a text value at a NUL, so `ada@x` and `ada@x\0anything` are one
 * value there and two on MySQL and SQLite — a validator that removed the NUL
 * would hand the unique index the first spelling and cause the collision it
 * exists to prevent.
 *
 * An exception rather than a ceremony outcome. The request step of both
 * ceremonies returns void so that it reveals nothing about who exists, so there
 * is no result channel to put this in; and neither malformation is an outcome of
 * anything — the value cannot be a subject, known or unknown.
 */
final class MalformedIdentifier extends InvalidArgumentException
{
    private function __construct(public readonly MalformedIdentifierReason $reason, string $message)
    {
        parent::__construct($message);
    }

    public static function invalidEncoding(): self
    {
        return new self(
            MalformedIdentifierReason::InvalidEncoding,
            'A submitted identifier is not valid UTF-8. Vouch refuses rather than repairing it: '
            . 'a substituted or dropped byte is a different identifier, and canonicalization of '
            . 'invalid text raises an unshaped library exception rather than a decision.',
        );
    }

    public static function forbiddenCharacter(): self
    {
        return new self(
            MalformedIdentifierReason::ForbiddenCharacter,
            'A submitted identifier contains a character an identifier cannot hold (a C0 control '
            . 'or DELETE). Vouch refuses rather than stripping it: PostgreSQL truncates text at a '
            . 'NUL, so a repaired spelling can land on somebody else\'s row under a unique index.',
        );
    }
}
