<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

/**
 * A token walk for clock reads, shared by the guards that forbid them.
 *
 * Two guards use it with different name lists: tests/Arch/DeadlineClockAuthorityTest
 * forbids NATIVE clock reads on the redeem paths, and
 * tests/Database/ThrottleReportCommandTest forbids APP clock reads in its own
 * fixtures. It was a private method on the first of those, then briefly a global
 * function in tests/Pest.php -- which broke `vendor/bin/phpunit` on the arch test,
 * because only Pest loads that file and PHPUnit's own bootstrap does not. Measured:
 * `Call to undefined function clockReadsIn()`. An autoloaded class is reachable from
 * either runner.
 *
 * @internal
 */
final class ClockReads
{
    /**
     * Clock reads in $source, over TOKENS rather than text so a mention in a
     * comment or a docblock is not a finding.
     *
     * @param  list<string>  $names  function names, lower case
     * @param  list<string>  $classes  class names whose construction or static call is a read, lower case
     * @param  list<string>  $prefixes  name PREFIXES, lower case: a whole family closed at once
     * @return list<string>
     */
    public static function in(string $source, array $names, array $classes, array $prefixes = []): array
    {
        $tokens = array_values(array_filter(
            token_get_all($source),
            static fn (array|string $token): bool => is_string($token)
                || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
    
        $found = [];
    
        foreach ($tokens as $index => $token) {
            if (is_array($token) && $token[0] === T_NEW) {
                $name = self::nameAfter($tokens, $index);
    
                /*
                 * The LAST SEGMENT as well as the whole name. `new \Carbon\Carbon()`
                 * arrives as one fully-qualified token, so comparing the whole string
                 * against a list of bare class names let it through -- measured, by
                 * injection, after the qualified-name token types had already been
                 * accepted for functions.
                 */
                $bare = strtolower(ltrim($name, '\\'));
                $segments = explode('\\', $bare);
    
                if (in_array($bare, $classes, true) || in_array(end($segments), $classes, true)) {
                    $found[] = 'new ' . $name;
                }
    
                continue;
            }
    
            /*
             * T_NAME_FULLY_QUALIFIED as well as T_STRING. `\date(...)` is the
             * ordinary spelling inside a namespaced file -- it needs no alias
             * and no indirection -- and scanning only T_STRING let exactly that
             * through.
             */
            if (! is_array($token) || ! in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED], true)) {
                continue;
            }
    
            $previous = $tokens[$index - 1] ?? null;
    
            /*
             * A STATIC call on a native date class is a clock read in the other
             * syntax: `\DateTimeImmutable::createFromFormat('', '')` returns
             * machine time as surely as `new DateTimeImmutable('now')` does, and
             * skipping every `::` let it through. The rule is the same one the
             * constructor check enforces -- these files do not touch the native
             * date classes -- so ask what the `::` is qualified BY rather than
             * skipping on sight.
             */
            if (is_array($previous) && $previous[0] === T_DOUBLE_COLON) {
                $owner = $tokens[$index - 2] ?? null;
                $ownerName = is_array($owner) ? $owner[1] : '';
    
                /*
                 * The LAST SEGMENT here too, and the omission was the same oversight
                 * one branch over: the `new` check above compares both and this one
                 * compared only the whole name, so `\Carbon\Carbon::now()` and
                 * `Date::now()` -- the idiomatic Laravel app clock -- went through.
                 * Measured, and a regression: two earlier versions of the calling guard
                 * caught `Date::now()` and the extraction lost it. The unconditional
                 * `continue` below is what makes it a silent miss rather than a partial
                 * one, because the function-name check never sees these names at all.
                 */
                $bareOwner = strtolower(ltrim($ownerName, '\\'));
                $ownerSegments = explode('\\', $bareOwner);
    
                /*
                 * And a '(' must follow, because a class CONSTANT is not a call:
                 * `DateTimeImmutable::ATOM` was reported as `DateTimeImmutable::ATOM()`
                 * -- a false positive inherited from the first version of this scan,
                 * where the `new` and bare-function branches both checked for the
                 * parenthesis and this one never did.
                 */
                if (($tokens[$index + 1] ?? null) === '('
                    && (in_array($bareOwner, $classes, true) || in_array(end($ownerSegments), $classes, true))) {
                    $found[] = $ownerName . '::' . $token[1] . '()';
                }
    
                continue;
            }
    
            /*
             * Any other qualified call belongs to somebody's injected authority
             * rather than being a native read, so `$this->time->date(...)` and
             * its nullsafe form are not findings. A declaration is not a call,
             * and `function &date()` puts a reference token in between. An
             * attribute name is not a call either.
             */
    
            // Compare the TEXT: PHP 8.4 emits a by-reference declaration's `&`
            // as T_AMPERSAND_NOT_FOLLOWED_BY_VAR_OR_VARARG rather than the bare
            // string, so matching the string alone missed `function &date()`.
            $previousText = is_array($previous) ? $previous[1] : $previous;
            $beforeReference = $previousText === '&' ? ($tokens[$index - 2] ?? null) : null;
    
            $qualified = is_array($previous) && in_array(
                $previous[0],
                [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_FUNCTION, T_ATTRIBUTE],
                true,
            );
    
            if ($qualified || (is_array($beforeReference) && $beforeReference[0] === T_FUNCTION)) {
                continue;
            }
    
            /*
             * By PREFIX as well as by name, because some families cannot be
             * enumerated. ext-intl reaches machine time through at least
             * intlcal_get_now(), intlcal_get_time(intlcal_create_instance()),
             * intlcal_from_date_time(), intlgregcal_create_instance() and a
             * calendar pulled out of datefmt_create() -- measured, each of them,
             * and four successive additions to the name list were each followed by
             * another spelling. A prefix closes the family by construction instead:
             * these files touch no intl at all, so naming the family costs nothing
             * and enumerating it never terminates.
             *
             * Prefixes are matched on TOKENS like everything else here, so the
             * comment you are reading -- which spells several of them out -- is not
             * itself a finding.
             */
            $callable = strtolower(ltrim($token[1], '\\'));
            $prefixed = false;

            foreach ($prefixes as $prefix) {
                if (str_starts_with($callable, $prefix)) {
                    $prefixed = true;

                    break;
                }
            }

            if (($tokens[$index + 1] ?? null) === '('
                && ($prefixed || in_array($callable, $names, true))) {
                $found[] = $token[1] . '()';
            }
        }
    
        return $found;
    }
    
    
    /**
     * The class name a `new` token introduces, or '' when it introduces none.
     *
     * @param  list<array{0: int, 1: string}|string>  $tokens
     */

    private static function nameAfter(array $tokens, int $index): string
    {
        $next = $tokens[$index + 1] ?? null;
    
        if (is_array($next) && in_array($next[0], [T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED], true)) {
            return $next[1];
        }
    
        return '';
    }
}
