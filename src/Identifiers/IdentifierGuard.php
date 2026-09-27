<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

/**
 * What bytes a submitted identifier may be made of, decided at the boundary.
 *
 * The other half of this question -- how LONG an identifier may be -- is
 * `ValueBoundViolation` through each model's `valueBounds()`, measured in
 * characters against the width of the column the value lands in. Two mechanisms
 * because the package already had that one, and a second length unit would only
 * give the two a way to disagree.
 *
 * Static, as `IssuanceLockBucket::for()` is and for the same reason: the callers
 * are readonly request objects and Eloquent mutators, neither of which takes
 * constructor injection, and this check reads no configuration at all.
 */
final class IdentifierGuard
{
    /**
     * The characters no identifier may contain.
     *
     * C0 controls (U+0000-U+001F) and DELETE. The NUL is the one the engines
     * disagree about -- PostgreSQL truncates a text value at it, MySQL and SQLite
     * keep it -- and the rest are in for the same reason it is rather than for
     * tidiness: none of them can be part of an address somebody types, and each
     * is a byte that some transport downstream of here treats as structure.
     *
     * C1 controls (U+0080-U+009F) are deliberately ABSENT. Measured: every engine
     * stores them byte-intact, so "refuse what the engine would silently alter"
     * does not reach them, and U+0085 NEL is not a line terminator to PCRE under
     * its default convention either. Refusing them would be a claim about a host's
     * mail transport that no measurement here supports.
     */
    private const string FORBIDDEN = '/[\x00-\x1f\x7f]/u';

    public static function assertWellFormed(string $submitted): void
    {
        /*
         * Encoding FIRST, and the order is load-bearing twice over. Invalid UTF-8
         * reaching IdentifierCanonicalizer raises Symfony's own
         * InvalidArgumentException -- an unshaped library exception on user input --
         * and the /u pattern below returns false rather than matching on a subject
         * that is not valid UTF-8, so a forbidden-character check placed first
         * would quietly pass every malformed sequence through.
         */
        if (! mb_check_encoding($submitted, 'UTF-8')) {
            throw MalformedIdentifier::invalidEncoding();
        }

        if (preg_match(self::FORBIDDEN, $submitted) === 1) {
            throw MalformedIdentifier::forbiddenCharacter();
        }
    }
}
