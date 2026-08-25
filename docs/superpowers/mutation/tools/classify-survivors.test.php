#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Self-contained assertions for classify-survivors.php.
 *
 * Deliberately free of Pest and PHPUnit: the reconciliation pin guards
 * `src/`, `tests/`, `composer.*`, `phpunit.xml`, `pest.php`, `config/` and
 * `database/`, and this tool must be landable without disturbing any of them.
 *
 * Run: php docs/superpowers/mutation/tools/classify-survivors.test.php
 */

$root = dirname(__DIR__, 4);
$tool = __DIR__ . '/classify-survivors.php';
$fixtures = __DIR__ . '/fixtures';

$failures = 0;
$assertions = 0;

function check(string $description, bool $passed): void
{
    global $failures, $assertions;

    $assertions++;

    if ($passed) {
        echo "  ok    {$description}", PHP_EOL;

        return;
    }

    $failures++;
    echo "  FAIL  {$description}", PHP_EOL;
}

/**
 * @return array{rows: array<string, array<string, mixed>>, exit: int, decoded: mixed}
 */
function classify(array $arguments): array
{
    global $tool, $root;

    $command = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($tool)
        . ' ' . implode(' ', array_map('escapeshellarg', $arguments))
        . ' ' . escapeshellarg('--source-root=' . $root) . ' --json 2>/dev/null';

    exec($command, $output, $status);

    $decoded = json_decode(implode("\n", $output), true);
    $rows = [];

    $decodedRows = is_array($decoded) && array_key_exists('rows', $decoded)
        ? $decoded['rows']
        : $decoded;

    foreach (is_array($decodedRows) ? $decodedRows : [] as $row) {
        $rows[$row['file'] . ':' . $row['line']] = $row;
    }

    return [
        'rows' => $rows,
        'exit' => $status,
        'decoded' => is_array($decoded) ? $decoded : [],
    ];
}

$store = 'src/Throttle/DatabaseAuthThrottleStore.php';
$strength = 'src/Kernel/Factor/FactorStrength.php';
$shaper = 'src/Kernel/Enumeration/ErrorShaper.php';

echo 'single measuring map', PHP_EOL;
$single = classify(["--log={$fixtures}/survivors.log", "--map={$fixtures}/sqlite.clover.xml"]);
check('exits 0', $single['exit'] === 0);
check('reads every survivor row', count($single['rows']) === 6);
check(
    'enum case declaration is instrument-unroutable',
    ($single['rows']["{$strength}:19"]['disposition'] ?? null) === 'instrument-unroutable'
);
check(
    'executable line with no hits is never-executed',
    ($single['rows']["{$shaper}:90"]['disposition'] ?? null) === 'never-executed'
);
check(
    'executed line with a surviving mutant is executed-and-survived',
    ($single['rows']["{$strength}:25"]['disposition'] ?? null) === 'executed-and-survived'
);
check(
    'engine-gated branch reads as never-executed without a union',
    ($single['rows']["{$store}:415"]['disposition'] ?? null) === 'never-executed'
);

check(
    'a timeout is never folded into a kill or a survivor',
    ($single['rows']["{$store}:409"]['disposition'] ?? null) === 'timeout-unresolved'
);
check(
    'a timeout is attributed to the file of its RUN heading',
    ($single['rows']["{$store}:409"]['file'] ?? null) === $store
);
$timeout = $single['rows']["{$store}:409"] ?? [];
check(
    'a timeout carries its mutator despite having no ID',
    ($timeout['mutator'] ?? null) === 'IfNegated'
        && array_key_exists('id', $timeout)
        && $timeout['id'] === null
);

echo PHP_EOL, 'the plugin outranks the coverage map for UNTESTED rows', PHP_EOL;
$signature = $single['rows']["{$store}:436"] ?? [];
check(
    'a survivor on a default parameter stays executed-and-survived',
    ($signature['disposition'] ?? null) === 'executed-and-survived'
);
check('the map is recorded as calling that line absent', ($signature['coverage'] ?? null) === 'absent');
check('the disagreement is surfaced rather than resolved away', ($signature['contested'] ?? null) === true);
check(
    'a survivor the map agrees with is not contested',
    ($single['rows']["{$strength}:25"]['contested'] ?? null) === false
);

echo PHP_EOL, 'union across engines', PHP_EOL;
$union = classify([
    "--log={$fixtures}/survivors.log",
    "--map={$fixtures}/sqlite.clover.xml",
    "--union={$fixtures}/mysql.clover.xml",
]);
check('exits 0', $union['exit'] === 0);
check(
    'DatabaseAuthThrottleStore.php:415 becomes engine-gated under the union',
    ($union['rows']["{$store}:415"]['disposition'] ?? null) === 'engine-gated'
);
check(
    'a genuine gap is not rescued by the union',
    ($union['rows']["{$shaper}:90"]['disposition'] ?? null) === 'never-executed'
);
check(
    'an unroutable row is not rescued by the union',
    ($union['rows']["{$strength}:19"]['disposition'] ?? null) === 'instrument-unroutable'
);
check(
    'a contested survivor is not reclassified by the union either',
    ($union['rows']["{$store}:436"]['disposition'] ?? null) === 'executed-and-survived'
);

echo PHP_EOL, 'baseline identity diff', PHP_EOL;
$baseline = tempnam(sys_get_temp_dir(), 'vouch-baseline-');
file_put_contents($baseline, json_encode(array_values($single['rows']), JSON_PRETTY_PRINT));
$diff = classify([
    "--log={$fixtures}/survivors.log",
    "--map={$fixtures}/sqlite.clover.xml",
    "--baseline={$baseline}",
]);
check('an identical classification has no added rows', ($diff['decoded']['baseline_diff']['added'] ?? null) === []);
check('an identical classification has no removed rows', ($diff['decoded']['baseline_diff']['removed'] ?? null) === []);
unlink($baseline);

echo PHP_EOL, 'identity is preserved', PHP_EOL;
$row = $union['rows']["{$store}:415"] ?? [];
check('mutator is carried', ($row['mutator'] ?? null) === 'RemoveEarlyReturn');
check('mutation id is carried', ($row['id'] ?? null) === 'aaaa111122223333');
check('state as reported by the plugin is carried', ($row['state'] ?? null) === 'UNCOVERED');
check(
    'expression is read from source, not inferred',
    ($row['expression'] ?? null) === 'if ($existedBeforeTransaction) {'
);

echo PHP_EOL, 'executed set in place of a map', PHP_EOL;
$set = classify(["--log={$fixtures}/survivors.log", "--lines={$fixtures}/union.lines"]);
check('exits 0', $set['exit'] === 0);
check(
    'a line in the set is executed-and-survived',
    ($set['rows']["{$strength}:25"]['disposition'] ?? null) === 'executed-and-survived'
);
check(
    'absence from a bare set cannot separate unroutable from a gap',
    ($set['rows']["{$shaper}:90"]['disposition'] ?? null) === 'indeterminate'
);

echo PHP_EOL, 'disagreeing maps are reported, not reconciled', PHP_EOL;
$bad = classify([
    "--log={$fixtures}/survivors.log",
    "--map={$fixtures}/sqlite.clover.xml",
    "--union={$fixtures}/inconsistent.clover.xml",
]);
check('exits 2', $bad['exit'] === 2);
check(
    'a line executable on one engine only is flagged inconsistent',
    ($bad['rows']["{$strength}:19"]['disposition'] ?? null) === 'inconsistent-map'
);

echo PHP_EOL, 'emitted union round-trips', PHP_EOL;
$emitted = tempnam(sys_get_temp_dir(), 'vouch-lines-');
classify([
    "--log={$fixtures}/survivors.log",
    "--map={$fixtures}/sqlite.clover.xml",
    "--union={$fixtures}/mysql.clover.xml",
    "--emit-lines={$emitted}",
]);
$written = file_get_contents($emitted) ?: '';
check('includes a line executed only on the second engine', str_contains($written, "{$store}:415"));
check('excludes a line executed on neither', ! str_contains($written, "{$shaper}:90"));
check('excludes a non-executable line', ! str_contains($written, "{$strength}:19"));
unlink($emitted);

echo PHP_EOL, 'reality anchor', PHP_EOL;
$source = (string) file_get_contents($root . '/' . $store);
check(
    'ensureIpParent still returns early on sqlite before the committed-row branch',
    (bool) preg_match(
        '/getDriverName\(\)\s*===\s*\'sqlite\'.*?return;.*?if\s*\(\$existedBeforeTransaction\)/s',
        $source
    )
);

echo PHP_EOL, sprintf('%d assertions, %d failures', $assertions, $failures), PHP_EOL;

exit($failures === 0 ? 0 : 1);
