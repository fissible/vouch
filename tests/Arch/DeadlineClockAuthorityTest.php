<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Arch;

use Fissible\Vouch\Tests\TestCase;
use PHPUnit\Framework\Attributes\Test;

/**
 * Issue #37 — the redeem paths may not read a clock of their own.
 *
 * `tests/Database/DeadlineClockSourceTest.php` proves the behaviour by skewing
 * application time against database time, and it controls the two application
 * clocks a Laravel package would normally reach for: the injected PSR clock and
 * Carbon. It cannot control a third. `new DateTimeImmutable('now')` reads the
 * machine clock directly, and a redeem path written that way compares a
 * database-written deadline against application time — the exact defect #37
 * fixes — while passing every behavioural test in that file.
 *
 * So this guard covers what a behavioural test structurally cannot: it is not a
 * second opinion about the same thing, it is the only check on that third
 * source. The two files are worth naming individually because both hold a
 * comparison against a deadline written by `DatabaseTime::deadline()`, which is
 * the pairing the issue is about.
 *
 * WHAT IT CANNOT DO, stated rather than implied, because a guard trusted past
 * its reach is worse than none:
 *
 *   - it reads these two files only. A helper elsewhere that reads native time
 *     and is called from here passes.
 *   - it recognises DIRECT calls, bare or fully qualified. A variable function
 *     name, a call reached through a `use function` alias, or
 *     `(new ReflectionClass(...))`-style indirection would evade it. So would a
 *     RENAMED class import (`use DateTimeImmutable as NativeDate`) or an
 *     anonymous subclass of a native date class: both are ordinary PHP, but
 *     neither serves any purpose in a fix for this issue, so they are recorded
 *     rather than chased.
 *   - the attribute skip handles `#[date(...)]` as the FIRST name in its group.
 *     A later name in `#[Foo, date(...)]` would need bracket tracking and is not
 *     attempted: that direction is a false positive rather than an escape, and
 *     no such code exists here.
 *   - it covers the native date classes through `new X` and `X::method()`,
 *     which are the two ways to OBTAIN time from them. A type hint or an
 *     `instanceof` naming one is not reported, because neither reads a clock.
 *   - it says nothing about WHICH authority is used, only that no native clock
 *     is read. Using the injected PSR clock for a deadline comparison is the
 *     original defect and remains a behavioural question, covered where the
 *     skew can actually be applied.
 */
final class DeadlineClockAuthorityTest extends TestCase
{
    /** Files whose deadline comparisons read a value written on the database clock. */
    private const REDEEM_FILES = [
        'src/Recovery/CredentialRecovery.php',
        'src/Verification/IdentifierVerifier.php',
    ];

    /**
     * Clock readers outside the date extension. Everything else comes from PHP
     * itself, below.
     */
    private const OTHER_NATIVE_CLOCK_FUNCTIONS = ['microtime', 'hrtime', 'gettimeofday'];

    private const NATIVE_CLOCK_CLASSES = ['datetime', 'datetimeimmutable'];

    /**
     * Every date-extension function, asked of PHP rather than listed by hand.
     *
     * A hand-written list was wrong twice: first it missed `\date(...)`, then it
     * had `date_create` but not `date_create_immutable`, and each time a redeem
     * path could have read the machine clock with no alias and no indirection
     * while this guard reported nothing. Enumerating the extension closes the
     * class instead of the instance, and cannot drift as PHP adds functions.
     *
     * It is deliberately broader than "clock reads": it also covers `date_diff`,
     * `date_format` and the timezone calls, which do not read a clock. The rule
     * these two files actually follow is stronger and easier to state -- they
     * call no date-extension function directly, and get time from an injected
     * authority -- so the wider net costs nothing and removes the judgement call
     * that got this wrong twice.
     *
     * @return list<string>
     */
    private function nativeClockFunctions(): array
    {
        $extension = get_extension_funcs('date');

        // Fail loudly rather than silently scanning for three names: a guard
        // that quietly lost most of its list is worse than one that is absent.
        self::assertIsArray($extension, 'PHP reported no date extension, so this guard cannot be built.');
        self::assertGreaterThan(20, count($extension));

        return array_map(
            static fn (string $name): string => strtolower($name),
            [...$extension, ...self::OTHER_NATIVE_CLOCK_FUNCTIONS],
        );
    }

    #[Test]
    public function redeem_paths_read_no_native_clock(): void
    {
        foreach (self::REDEEM_FILES as $file) {
            $path = dirname(__DIR__, 2) . '/' . $file;
            $source = file_get_contents($path);

            self::assertIsString($source, $file . ' could not be read.');

            foreach ($this->nativeClockReads($source, $this->nativeClockFunctions()) as $found) {
                self::fail(sprintf(
                    '%s reads the machine clock through %s. A deadline written by DatabaseTime '
                    . 'must be compared against the database clock; native time cannot be skewed '
                    . 'by any test, so this would pass the behavioural suite while restoring the '
                    . 'defect. Use DatabaseTime.',
                    $file,
                    $found,
                ));
            }

            // The file really was scanned: a path typo or an empty read would
            // otherwise report "no native clock" about nothing at all.
            self::assertNotSame([], token_get_all($source));
        }
    }

    /**
     * Native clock reads, over tokens rather than text so a mention in a comment
     * or a docblock is not a finding.
     *
     * @param  list<string>  $nativeFunctions
     * @return list<string>
     */
    private function nativeClockReads(string $source, array $nativeFunctions): array
    {
        $tokens = array_values(array_filter(
            token_get_all($source),
            static fn (array|string $token): bool => is_string($token)
                || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));

        $found = [];

        foreach ($tokens as $index => $token) {
            if (is_array($token) && $token[0] === T_NEW) {
                $name = $this->nameAfter($tokens, $index);

                if (in_array(strtolower(ltrim($name, '\\')), self::NATIVE_CLOCK_CLASSES, true)) {
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

                if (in_array(strtolower(ltrim($ownerName, '\\')), self::NATIVE_CLOCK_CLASSES, true)) {
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

            if (($tokens[$index + 1] ?? null) === '('
                && in_array(strtolower(ltrim($token[1], '\\')), $nativeFunctions, true)) {
                $found[] = $token[1] . '()';
            }
        }

        return $found;
    }

    /** @param list<array{0: int, 1: string, 2: int}|string> $tokens */
    private function nameAfter(array $tokens, int $index): string
    {
        $next = $tokens[$index + 1] ?? null;

        if (is_array($next) && in_array($next[0], [T_STRING, T_NAME_FULLY_QUALIFIED, T_NAME_QUALIFIED], true)) {
            return $next[1];
        }

        return '';
    }
}
