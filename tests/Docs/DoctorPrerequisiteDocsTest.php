<?php

declare(strict_types=1);

use Illuminate\Foundation\Testing\RefreshDatabase;
use Fissible\Vouch\Tests\Support\PrerequisiteTable;
use Illuminate\Support\Facades\Config;

/*
 * The database trait is not decoration. This test runs the doctor command, which
 * counts identifier rows, so without migrations the command exits 2 and prints a
 * human error line where the test expects JSON. It passed without this only
 * because another file had already migrated the shared scratch database -- found
 * by running tests/Docs on its own, which is the run that has nobody to inherit
 * from.
 */
uses(RefreshDatabase::class);

/*
 * #82. The operator-facing prerequisite table and the command must agree.
 *
 * docs/operations.md tells a host which prerequisites to establish and says to run
 * vouch:doctor to check them together. A row the command reports but the table does
 * not describe is a prerequisite an operator is told about only once it fails, with
 * no guidance on what to do; a row in the table the command never reports is advice
 * about a check nobody runs.
 *
 * Both directions are asserted, because they fail differently. The first is what
 * #82 itself created -- three new rows, one document unchanged -- and nothing in
 * the suite noticed. The second is what happens when a check is retired.
 *
 * Reads the shipped file rather than a fixture: the question is what the document a
 * host actually gets says, which no copy can answer.
 */

it('describes every prerequisite the doctor can report', function (): void {
    /*
     * Every feature on, so the conditional rows are present. Without this the two
     * feature-gated prerequisites would be absent from the report and the assertion
     * would hold while the document said nothing about them.
     */
    Config::set('vouch.throttle.captcha.enabled', true);
    Config::set('vouch.throttle.global.mode', 'enforce');
    Config::set('vouch.throttle.global.enforce_at', 5);
    Config::set('vouch.throttle.global.backoff_seconds', 1);
    Config::set('vouch.assurance_strict', true);
    app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);

    $reported = array_keys(doctorRows());

    // The premise: every feature really is on, so this is the whole row set rather
    // than the default subset.
    expect($reported)->toContain('CaptchaVerifier');
    expect($reported)->toContain('vouch.declared_abilities');

    $operations = file_get_contents(dirname(__DIR__, 2) . '/docs/operations.md');

    if (! is_string($operations)) {
        throw new RuntimeException('docs/operations.md is unreadable.');
    }

    $table = PrerequisiteTable::names($operations);

    // The premise: the table was found and parsed, so a difference below is a real
    // disagreement rather than a regex that matched nothing.
    expect($table)->toContain('verified_at');

    /*
     * No message arguments on toContain: it is VARIADIC, so a second argument becomes
     * another value the array must contain, and the failure then reports the message
     * text as the missing needle. Sorted comparisons instead, which name both
     * directions of the disagreement in one diff.
     */
    $reportedNames = $reported;
    $documentedNames = $table;
    sort($reportedNames);
    sort($documentedNames);

    expect($documentedNames)->toBe($reportedNames);
});

/*
 * #95. The helper above claims a row written as prose "is invisible here and fails the
 * comparison". Only the first half was true.
 *
 * A row whose first cell is not a code span was SKIPPED, so the extracted names were
 * unchanged and the sorted comparison still passed. That catches a row the command
 * reports and the document omits -- the name is then missing from the documented list
 * -- but not a row the document INVENTS, which is advice about a check nobody runs.
 * One of the two claimed directions was unenforced, and the docblock asserting
 * otherwise was written in response to a review finding, which makes it the more
 * misleading for being deliberate.
 *
 * The cases below run the helper against synthetic documents rather than the shipped
 * one: the requirement is about what the helper REJECTS, and the shipped file is
 * (correctly) not an example of any of it.
 */

/** A prerequisite table in the shape the helper looks for, with $rows between the pipes. */
function prerequisiteDocument(string ...$rows): string
{
    return "Preamble.\n\n| Prerequisite | Host responsibility |\n|---|---|\n" . implode("\n", $rows) . "\n\nTrailer.\n";
}

it('parses a well-formed prerequisite table', function (): void {
    /*
     * The positive control, and it is not decoration: every rejection below has to be
     * the helper refusing a bad row rather than the synthetic document missing the
     * shape the helper looks for at all, which would throw for the wrong reason and
     * read identically.
     */
    expect(PrerequisiteTable::names(prerequisiteDocument(
        '| `durable_queue` | Configure a non-sync queue. |',
        '| `vouch.declared_abilities` | Declare every mapped ability. |',
    )))->toBe(['durable_queue', 'vouch.declared_abilities']);
});

/**
 * Render $document the way an operator's Markdown viewer does.
 *
 * Asked of a renderer rather than asserted from the shape of the string, because the
 * question each case below asks is whether a READER sees the row. Markdown has more
 * ways to spell a table row than a regular expression tends to anticipate -- a leading
 * pipe is optional, up to three spaces of indentation are ignored -- and a guard that
 * disagrees with the renderer about what is in the table is the defect, not the test.
 */
function renderedMarkdown(string $document): string
{
    $environment = new \League\CommonMark\Environment\Environment;
    $environment->addExtension(new \League\CommonMark\Extension\CommonMark\CommonMarkCoreExtension);
    $environment->addExtension(new \League\CommonMark\Extension\Table\TableExtension);

    return (new \League\CommonMark\MarkdownConverter($environment))->convert($document)->getContent();
}

it('rejects every row the renderer puts in the table whose name is not a code span', function (string $row, string $visible, string $named): void {
    /*
     * #95, stated as the class rather than as a list of spellings.
     *
     * The original helper SKIPPED a row it could not parse, so an invented
     * prerequisite left the extracted names unchanged and the sorted comparison still
     * passed. Three further spellings were then found one at a time, each slipping
     * past the fix for the last: text beside the code span, a row indented by one
     * space, and a row with no leading pipe at all. The first was a parsing
     * tolerance; the other two ended the captured block early, so the row was never
     * offered to the first-cell rule at all.
     *
     * So the requirement is not "reject these four". It is that every row the RENDERER
     * treats as part of the prerequisite table must be accounted for, and any such row
     * whose first cell is not a code span must be refused by name. Each case proves
     * both halves: that an operator sees the row, and that the guard names it.
     */
    $document = prerequisiteDocument(
        '| `durable_queue` | Configure a non-sync queue. |',
        $row,
    );

    // The premise: a reader really does see this row, so refusing it is not pedantry
    // about Markdown style.
    expect(renderedMarkdown($document))->toContain('<td>' . $visible . '</td>');

    expect(fn (): array => PrerequisiteTable::names($document))
        ->toThrow(RuntimeException::class, $named);
})->with([
    'a prose first cell' => [
        '| Unreported prerequisite | Must configure this too. |',
        'Unreported prerequisite',
        'Unreported prerequisite',
    ],
    'text beside the code span' => [
        '| `durable_queue` and friends | Configure a non-sync queue. |',
        '<code>durable_queue</code> and friends',
        'and friends',
    ],
    'an indented row' => [
        ' | Unreported prerequisite | Must configure this too. |',
        'Unreported prerequisite',
        'Unreported prerequisite',
    ],
    'no leading pipe' => [
        'Unreported prerequisite | Must configure this too. |',
        'Unreported prerequisite',
        'Unreported prerequisite',
    ],
]);

it('names the offending row in full rather than only refusing', function (): void {
    /*
     * Asserted separately from the rejections above, where the needle is only the part
     * of the row that made it invalid. A guard that fails without quoting the row sends
     * a reader to diff the table by eye.
     */
    expect(fn (): array => PrerequisiteTable::names(prerequisiteDocument(
        '| `durable_queue` | Configure a non-sync queue. |',
        '| Invented row | Nothing reports this. |',
    )))->toThrow(RuntimeException::class, '| Invented row | Nothing reports this. |');
});
