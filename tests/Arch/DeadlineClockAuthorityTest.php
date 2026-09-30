<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Arch;

use Fissible\Vouch\Tests\Support\ClockReads;
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
     * Native clock reads in $source.
     *
     * The scan itself lives in Support\ClockReads, because a second file needs it:
     * ThrottleReportCommandTest guards its own fixtures against the APP clock with
     * the same token walk over a different name list. A second, weaker copy was
     * written first and reproduced a hole this one had already closed -- it scanned
     * T_STRING only, so every `\DateTimeImmutable` spelling went through. A class
     * rather than a global in tests/Pest.php, because only Pest loads that file:
     * measured, `vendor/bin/phpunit` on this test then failed with
     * `Call to undefined function`.
     *
     * @param  list<string>  $nativeFunctions
     * @return list<string>
     */
    private function nativeClockReads(string $source, array $nativeFunctions): array
    {
        return ClockReads::in($source, $nativeFunctions, self::NATIVE_CLOCK_CLASSES);
    }
}
