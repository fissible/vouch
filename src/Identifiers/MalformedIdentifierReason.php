<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

/**
 * Why a submitted identifier was refused before anything read it.
 *
 * Two cases rather than one opaque refusal, because a host has to render them
 * differently: "that address contains characters it cannot contain" and "that is
 * not valid text" are different things for somebody to fix, and one reason makes
 * every message the same.
 *
 * Deliberately not a length case. Length is `ValueBoundViolation`, measured per
 * column in characters, which is the mechanism this package already had.
 */
enum MalformedIdentifierReason
{
    /** Not valid UTF-8: a lone continuation byte, a truncated or overlong sequence, a surrogate. */
    case InvalidEncoding;

    /** Valid UTF-8 carrying a character no identifier may hold — a C0 control, or DELETE. */
    case ForbiddenCharacter;
}
