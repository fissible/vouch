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
 *   - it recognises the spellings below. `(new ReflectionClass(...))`-style
 *     indirection, a variable function name, or a native call reached through
 *     an alias would evade it.
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

    /** Native reads of the machine clock, which no injected authority can move. */
    private const NATIVE_CLOCK_FUNCTIONS = [
        'time', 'date', 'mktime', 'gmmktime', 'gmdate',
        'microtime', 'hrtime', 'strtotime', 'getdate', 'localtime', 'date_create',
    ];

    private const NATIVE_CLOCK_CLASSES = ['datetime', 'datetimeimmutable'];

    #[Test]
    public function redeem_paths_read_no_native_clock(): void
    {
        foreach (self::REDEEM_FILES as $file) {
            $path = dirname(__DIR__, 2) . '/' . $file;
            $source = file_get_contents($path);

            self::assertIsString($source, $file . ' could not be read.');

            foreach ($this->nativeClockReads($source) as $found) {
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
     * @return list<string>
     */
    private function nativeClockReads(string $source): array
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

            if (! is_array($token) || $token[0] !== T_STRING) {
                continue;
            }

            // A method or static call is qualified by an object or a class, and
            // is therefore somebody's injected authority rather than a native
            // read: `$this->time->date(...)` must not be reported here.
            $previous = $tokens[$index - 1] ?? null;
            if (is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true)) {
                continue;
            }

            if (($tokens[$index + 1] ?? null) === '('
                && in_array(strtolower($token[1]), self::NATIVE_CLOCK_FUNCTIONS, true)) {
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
