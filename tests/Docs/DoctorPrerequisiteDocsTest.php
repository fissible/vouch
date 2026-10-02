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

/*
 * #99. The four spellings above are regression coverage; the requirement is the class.
 *
 * Measured during #95's review: a capture requiring two pipes per row passed every one
 * of those four and still missed `Unreported prerequisite | Must configure this too.`,
 * which CommonMark renders as a table row. The shipped helper derives membership from
 * the parser and is correct -- but it is correct because it satisfies the requirement
 * the case name states, not because those four inputs force it. A later reader could
 * swap in a pattern, pass everything, and reinstate the defect.
 *
 * So the renderer is the ORACLE, over generated documents, in both directions. The
 * generator supplies the valid/invalid distinction; the renderer decides membership;
 * the helper has to agree. The test never reconstructs a table boundary or walks the
 * AST, which is what would make it a second implementation of the thing under test.
 *
 * What this does NOT establish: correctness for arbitrary Markdown. Coverage is the
 * generator's, and a generator is finite. It is a far wider net than four rows, not a
 * proof.
 */

/** The table header the helper selects on. Fixed, not generated -- see below. */
const PREREQUISITE_HEADER = '| Prerequisite | Host responsibility |';

/**
 * Every prerequisite row the renderer emits, as the name it yields and the text it says.
 *
 * `name` is the first column's content when the cell IS exactly one code span, and '' when
 * it is anything else -- prose, text beside a span, two spans, a span inside emphasis, or
 * nothing at all. `text` is the whole row's text, which is how a case identifies the row
 * it planted when the first cell cannot carry a marker because it is empty.
 *
 * Structural, not textual, and measured: `*`x`*` renders `<em><code>x</code></em>`, whose
 * text is identical to a bare span's, so a text comparison called it a clean name while
 * the helper -- correctly -- refuses it.
 *
 * @return list<array{name: string, text: string}>
 */
function renderedPrerequisiteRows(string $document): array
{
    $dom = new DOMDocument;
    // A rendered fragment has no root and no doctype; neither is an error worth surfacing,
    // and libxml would otherwise warn about both.
    $previous = libxml_use_internal_errors(true);
    $dom->loadHTML('<!doctype html><html><body>' . renderedMarkdown($document) . '</body></html>');
    libxml_clear_errors();
    libxml_use_internal_errors($previous);

    $rows = [];

    foreach (iterator_to_array($dom->getElementsByTagName('table')) as $table) {
        $head = $table->getElementsByTagName('thead')->item(0);

        if (! $head instanceof DOMElement || ! str_contains($head->textContent, 'Prerequisite')) {
            continue;
        }

        foreach (iterator_to_array($table->getElementsByTagName('tbody')) as $body) {
            foreach (iterator_to_array($body->getElementsByTagName('tr')) as $row) {
                $cell = $row->getElementsByTagName('td')->item(0);
                $only = $cell instanceof DOMElement && $cell->childNodes->length === 1
                    ? $cell->firstChild
                    : null;

                $rows[] = [
                    'name' => $only instanceof DOMElement && $only->tagName === 'code'
                        ? $only->textContent
                        : '',
                    'text' => $row->textContent,
                ];
            }
        }
    }

    return $rows;
}

/**
 * The names the renderer yields, in order.
 *
 * @return list<string>
 */
function renderedPrerequisiteNames(string $document): array
{
    return array_map(
        static fn (array $row): string => $row['name'],
        renderedPrerequisiteRows($document),
    );
}

/**
 * A GRAMMAR of body-row spellings, not a list of examples.
 *
 * Five rounds of review each found another axis I had not generated -- position, tabs,
 * cell count, then leading-pipe-only, unpadded and surplus cells in one round. That is
 * enumeration, and it does not terminate. So the axes are crossed as a grammar and the
 * RENDERER decides which products are in scope: a form the renderer does not put in the
 * table has nothing for the helper to refuse, and the cases below skip it rather than
 * counting it against anyone. Widening this can therefore only add coverage.
 *
 * Every axis is measured against the installed renderer. A body row stays in the table
 * with any leading whitespace (12 spaces, and 1 024), with tabs and mixed tab/space
 * prefixes, with either outer pipe absent, with its second cell empty or omitted, with no
 * padding around the pipes, and with surplus cells.
 *
 * Returned as STRUCTURED axes rather than only a name, because coverage has to be counted
 * per axis value and a name is a string: measured, counting by substring let
 * `no leading pipe` satisfy `leading pipe` and `space then tab` satisfy `tab`, so the
 * coverage assertion passed with whole axes missing.
 *
 * @return array<string, array{prefix: string, prefixName: string, leading: bool, trailing: bool, cells: int, padded: bool}>
 */
function prerequisiteRowForms(): array
{
    $prefixes = [
        'flush' => '',
        'one space' => ' ',
        'four spaces' => '    ',
        'twelve spaces' => '            ',
        'tab' => "\t",
        'space then tab' => " \t",
    ];
    $forms = [];

    foreach ($prefixes as $prefixName => $prefix) {
        foreach ([true, false] as $leading) {
            foreach ([true, false] as $trailing) {
                foreach ([1, 2, 3] as $cells) {
                    foreach ([true, false] as $padded) {
                        $forms[sprintf(
                            '%s, %s, %s, %d cell(s), %s',
                            $prefixName,
                            $leading ? 'leading pipe' : 'no leading pipe',
                            $trailing ? 'trailing pipe' : 'no trailing pipe',
                            $cells,
                            $padded ? 'padded' : 'tight',
                        )] = [
                            'prefix' => $prefix,
                            'prefixName' => $prefixName,
                            'leading' => $leading,
                            'trailing' => $trailing,
                            'cells' => $cells,
                            'padded' => $padded,
                        ];
                    }
                }
            }
        }
    }

    return $forms;
}

/**
 * The plainest form there is, used as the OTHER side of every transition.
 *
 * @return array{prefix: string, prefixName: string, leading: bool, trailing: bool, cells: int, padded: bool}
 */
function prerequisiteBaselineForm(): array
{
    return [
        'prefix' => '',
        'prefixName' => 'flush',
        'leading' => true,
        'trailing' => true,
        'cells' => 2,
        'padded' => true,
    ];
}

/**
 * One body row, spelled as $form says.
 *
 * @param  array{prefix: string, prefixName: string, leading: bool, trailing: bool, cells: int, padded: bool}  $form
 */
function prerequisiteRow(string $cell, array $form): string
{
    $pad = $form['padded'] ? ' ' : '';
    $contents = [$cell];

    for ($extra = 1; $extra < $form['cells']; $extra++) {
        $contents[] = 'Host responsibility ' . $extra;
    }

    $row = $form['prefix'] . ($form['leading'] ? '|' . $pad : '');
    $row .= implode($pad . '|' . $pad, $contents);

    return $row . ($form['trailing'] ? $pad . '|' : '');
}

/**
 * A prerequisite document with the given body rows.
 *
 * The header is fixed on purpose: it is what selects the table, and a header the helper
 * does not recognise makes it throw "no prerequisite table in the expected shape" --
 * loud, and the safe direction. Generating that would test table discovery rather than
 * membership.
 *
 * @param  list<string>  $rows
 */
function generatedPrerequisiteDocument(array $rows): string
{
    return implode("\n", [
        'Preamble about operating the package.',
        '',
        PREREQUISITE_HEADER,
        '|---|---|',
        ...$rows,
        '',
        'Trailing prose.',
    ]) . "\n";
}

/**
 * Assert every value of every grammar axis was actually exercised.
 *
 * Counted from the STRUCTURED form rather than from its name, and that is a correction:
 * measured, substring counting let `no leading pipe` satisfy `leading pipe`,
 * `no trailing pipe` satisfy `trailing pipe` and `space then tab` satisfy `tab`, so this
 * passed with 64 of 144 forms and whole axes missing. A control that cannot fail is worse
 * than none, because it reads as coverage.
 *
 * Aggregate floors are not enough either: a floor of fifty tolerated losing every
 * no-leading-pipe form, since seventy-two remain.
 *
 * @param  list<array{prefix: string, prefixName: string, leading: bool, trailing: bool, cells: int, padded: bool}>  $exercised
 */
function expectEveryFormAxisExercised(array $exercised): void
{
    $seen = ['prefixName' => [], 'leading' => [], 'trailing' => [], 'cells' => [], 'padded' => []];

    foreach ($exercised as $form) {
        foreach (array_keys($seen) as $axis) {
            $seen[$axis][] = is_bool($form[$axis]) ? ($form[$axis] ? 'yes' : 'no') : (string) $form[$axis];
        }
    }

    expect(array_values(array_unique($seen['prefixName'])))
        ->toEqualCanonicalizing(['flush', 'one space', 'four spaces', 'twelve spaces', 'tab', 'space then tab']);
    expect(array_values(array_unique($seen['leading'])))->toEqualCanonicalizing(['yes', 'no']);
    expect(array_values(array_unique($seen['trailing'])))->toEqualCanonicalizing(['yes', 'no']);
    expect(array_values(array_unique($seen['cells'])))->toEqualCanonicalizing(['1', '2', '3']);
    expect(array_values(array_unique($seen['padded'])))->toEqualCanonicalizing(['yes', 'no']);
}

it('names exactly the rows the renderer puts in the table, however they are spelled', function (): void {
    /*
     * The positive half, load-bearing three times over. Without it an implementation that
     * always throws satisfies every rejection case here. Without more than one row per
     * document it cannot see ORDER or MULTIPLICITY -- measured, a helper ending in
     * `array_values(array_unique($names))` survived the single-row version across all 136
     * accepted forms, reducing ['zeta', 'alpha', 'zeta'] to two. And without MIXED forms
     * inside one document it cannot see a transition: measured, a helper that stops when a
     * row's indentation switches between containing a tab and not containing one passed
     * every case while silently dropping rows.
     *
     * So each document alternates the form under test with the plainest form there is, and
     * carries a repeated name as well as distinct ones.
     */
    $sequence = ['zeta', 'alpha', 'zeta', 'omega'];
    $exercised = [];
    $disagreed = [];

    foreach (prerequisiteRowForms() as $name => $form) {
        $rows = [];

        foreach ($sequence as $index => $prereq) {
            $rows[] = prerequisiteRow(
                '`' . $prereq . '`',
                $index % 2 === 0 ? prerequisiteBaselineForm() : $form,
            );
        }

        $document = generatedPrerequisiteDocument($rows);
        $oracle = renderedPrerequisiteNames($document);

        if ($oracle !== $sequence) {
            continue;
        }

        $exercised[] = $form;

        try {
            $actual = PrerequisiteTable::names($document);
        } catch (RuntimeException $refusal) {
            $disagreed[] = $name . ' (refused rows the renderer named: ' . $refusal->getMessage() . ')';

            continue;
        }

        if ($actual !== $oracle) {
            $disagreed[] = $name . ' (named ' . json_encode($actual, JSON_THROW_ON_ERROR) . ')';
        }
    }

    // The premises: the grammar produced real table rows, and every axis of it did.
    expect(count($exercised))->toBeGreaterThan(50);
    expectEveryFormAxisExercised($exercised);

    expect($disagreed)->toBe([]);
});

it('refuses any row the renderer puts in the table whose first cell is not one code span', function (string $cell, string $position): void {
    /*
     * The negative half, over every form the renderer accepts, at every POSITION, with the
     * surrounding valid rows in the plainest form so each document contains a TRANSITION
     * into and out of the form under test.
     *
     * Three measurements shaped this. A version that always put the invalid row between
     * two valid ones let a helper skipping an invalid FIRST body row survive while
     * accepting 136 first-row and 136 sole-row forms. A gate requiring the marker in the
     * FIRST cell could not reach the shape that has no first-cell content, which 132
     * renderer-visible forms produce and a counter skipping null first-cell nodes accepted
     * 84 of. And reusing one form for every row in a document hid a helper that stops at a
     * change of indentation style.
     *
     * Failures are COLLECTED: asserting per form stopped at the first one and reported only
     * `Exception "RuntimeException" not thrown`, with the form nowhere in the output.
     */
    $exercised = [];
    $survived = [];
    $baseline = prerequisiteBaselineForm();

    foreach (prerequisiteRowForms() as $name => $form) {
        $marker = 'invented' . substr(md5($name . $position), 0, 10);
        $invalid = prerequisiteRow(str_replace('MARKER', $marker, $cell), $form);
        $valid = prerequisiteRow('`prereq_valid`', $baseline);

        $rows = match ($position) {
            'sole' => [$invalid],
            'first' => [$invalid, $valid],
            'middle' => [$valid, $invalid, $valid],
            'last' => [$valid, $invalid],
            default => throw new InvalidArgumentException('Unknown position "' . $position . '".'),
        };

        $document = generatedPrerequisiteDocument($rows);
        $rendered = renderedPrerequisiteRows($document);

        /*
         * In scope only if the renderer emitted every row AND the planted one is reported
         * as no name at all. A form the renderer drops has nothing to refuse, and counting
         * it as a survivor would fail this for the renderer's choices rather than the
         * helper's.
         */
        if (count($rendered) !== count($rows)) {
            continue;
        }

        $empty = $cell === '';
        $planted = null;

        foreach ($rendered as $row) {
            if (str_contains($row['text'], $marker)) {
                $planted = $row;
            }
        }

        if (! $empty && ($planted === null || $planted['name'] !== '')) {
            continue;
        }

        if ($empty && array_filter($rendered, static fn (array $row): bool => $row['name'] === '') === []) {
            continue;
        }

        $exercised[] = $form;

        try {
            PrerequisiteTable::names($document);
            $survived[] = $name . ' (accepted)';
        } catch (RuntimeException $refusal) {
            if (! $empty && ! str_contains($refusal->getMessage(), $marker)) {
                $survived[] = $name . ' (refused without naming the row)';
            }
        }
    }

    // The premises again: a shape whose every form the renderer dropped would otherwise
    // pass having tested nothing, and an axis silently lost would hide behind a total.
    expect(count($exercised))->toBeGreaterThan(20);
    expectEveryFormAxisExercised($exercised);

    expect($survived)->toBe([]);
})->with(function (): Generator {
    foreach ([
        'prose first cell' => 'MARKER',
        'text after the span' => '`prereq_c` MARKER',
        'text before the span' => 'MARKER `prereq_d`',
        'two spans' => '`MARKER` `prereq_e`',
        'emphasis around the span' => '*`MARKER`*',
        'empty first cell' => '',
    ] as $shape => $cell) {
        foreach (['sole', 'first', 'middle', 'last'] as $position) {
            yield $shape . ', ' . $position => [$cell, $position];
        }
    }
});
