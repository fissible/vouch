<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Config;

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

    $table = prerequisiteTableOf($operations);

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

/**
 * The prerequisite names the operations table documents.
 *
 * Only the first column of the prerequisite table, and only its backticked names:
 * one row is prose ("Durable asynchronous queue") describing the `durable_queue`
 * check, so the names are read from the code spans an operator can search for.
 *
 * @return list<string>
 */
function prerequisiteTableOf(string $operations): array
{
    if (preg_match('/\| Prerequisite \| Host responsibility \|\n\|[-|]+\|\n((?:\|.*\n)+)/', $operations, $matches) !== 1) {
        throw new RuntimeException('docs/operations.md has no prerequisite table in the expected shape.');
    }

    $names = [];

    foreach (explode("\n", trim($matches[1])) as $line) {
        if (preg_match('/^\| `([^`]+)`/', $line, $cell) === 1) {
            $names[] = $cell[1];
        }
    }

    return $names;
}
