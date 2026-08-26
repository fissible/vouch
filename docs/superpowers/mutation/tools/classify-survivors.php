#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Classify mutation survivor rows against one or more Clover coverage maps.
 *
 * The reconciliation ledger (docs/superpowers/mutation/2026-08-22-reconciliation-ledger.md)
 * requires every emitted row to carry a stable disposition. Three of those
 * dispositions are mechanically decidable from coverage rather than by hand:
 *
 *   instrument-unroutable   the line is absent from the coverage map entirely.
 *                           Enum case declarations, class constants and the
 *                           `match (true)` line itself are not executable, so
 *                           no test can ever be routed to a mutant on them.
 *                           This is an instrument limit, never a verdict.
 *
 *   never-executed          the line is in the map with a zero hit count. The
 *                           code is executable and no test reaches it. This is
 *                           a genuine gap.
 *
 *   executed-and-survived   the line is in the map with a positive hit count.
 *                           Tests run it and the mutant lived anyway, so the
 *                           assertions are too weak. This is the only bucket
 *                           mutation testing is actually reporting on.
 *
 * A fourth disposition is derived by comparing engines. A line that is
 * never-executed under the measuring engine but executed under another is
 * engine-gated, not a gap — see DatabaseAuthThrottleStore::ensureIpParent(),
 * whose committed-row branch is unreachable on SQLite by construction.
 *
 * Usage:
 *   classify-survivors.php --log=FILE (--map=CLOVER | --lines=SET)
 *                          [--union=CLOVER]... [--source-root=DIR]
 *                          [--emit-lines=FILE] [--baseline=JSON]
 *                          [--baseline-identity=line|expression] [--json]
 *
 *   --log          de-ANSI'd non-compact mutation log. Compact/parallel output
 *                  suppresses the row list and cannot be classified.
 *   --map          Clover report from the engine that produced --log. Required
 *                  for full resolution.
 *   --union        additional Clover reports from other engines. Repeatable.
 *   --lines        a precomputed unioned executed set, one `path:line` per
 *                  line. Usable in place of --map at reduced resolution, or
 *                  alongside it as the union source.
 *   --source-root  root the Clover paths and log paths resolve against.
 *                  Defaults to the current working directory.
 *   --emit-lines   write the unioned executed set to FILE for reuse.
 *   --baseline     prior classification JSON; report added/removed row
 *                  identities (file, line, mutator) against this run.
 *   --baseline-identity  line (default) identifies file/line/mutator rows and
 *                        preserves duplicate occurrences by ordinal;
 *                        expression tolerates line shifts after a source edit
 *                        and likewise preserves repeated expressions.
 *   --json         emit rows as JSON instead of a grouped report.
 *
 * Exit codes: 0 classified, 1 usage error, 2 map inconsistency detected.
 */

const DISPOSITIONS = [
    'instrument-unroutable',
    'never-executed',
    'engine-gated',
    'executed-and-survived',
    'timeout-unresolved',
    'indeterminate',
    'inconsistent-map',
];

/**
 * @return array{log: string, map: ?string, union: list<string>, lines: ?string,
 *               root: string, emit: ?string, baseline: ?string,
 *               baselineIdentity: string, json: bool}
 */
function parseArguments(array $argv): array
{
    $options = ['log' => null, 'map' => null, 'union' => [], 'lines' => null,
        'root' => getcwd(), 'emit' => null, 'baseline' => null,
        'baselineIdentity' => 'line', 'json' => false];

    foreach (array_slice($argv, 1) as $argument) {
        if ($argument === '--json') {
            $options['json'] = true;

            continue;
        }

        if (! preg_match('/^--([a-z-]+)=(.*)$/', $argument, $matches)) {
            fail("Unrecognized argument: {$argument}");
        }

        [, $name, $value] = $matches;

        match ($name) {
            'log' => $options['log'] = $value,
            'map' => $options['map'] = $value,
            'union' => $options['union'][] = $value,
            'lines' => $options['lines'] = $value,
            'source-root' => $options['root'] = rtrim($value, '/'),
            'emit-lines' => $options['emit'] = $value,
            'baseline' => $options['baseline'] = $value,
            'baseline-identity' => $options['baselineIdentity'] = $value,
            default => fail("Unrecognized option: --{$name}"),
        };
    }

    if ($options['log'] === null) {
        fail('--log is required.');
    }

    if ($options['map'] === null && $options['lines'] === null) {
        fail('Either --map or --lines is required.');
    }

    if (! in_array($options['baselineIdentity'], ['line', 'expression'], true)) {
        fail('--baseline-identity must be line or expression.');
    }

    return $options;
}

function fail(string $message): never
{
    fwrite(STDERR, $message . PHP_EOL);
    exit(1);
}

/**
 * Normalize a Clover file name to a path relative to the source root, so that
 * map keys and log keys are comparable.
 */
function relativize(string $path, string $root): string
{
    if ($root !== '' && str_starts_with($path, $root . '/')) {
        $path = substr($path, strlen($root) + 1);
    }

    return ltrim($path, './');
}

/**
 * Read a Clover report into file => line => hit count.
 *
 * Only `stmt` lines are read. A line absent from this structure is not
 * executable, which is the distinction the unroutable disposition rests on.
 *
 * @return array<string, array<int, int>>
 */
function readClover(string $path, string $root): array
{
    if (! is_file($path)) {
        fail("Clover report not found: {$path}");
    }

    $previous = libxml_use_internal_errors(true);
    $document = simplexml_load_string((string) file_get_contents($path));
    libxml_use_internal_errors($previous);

    if ($document === false) {
        fail("Clover report is not valid XML: {$path}");
    }

    $map = [];

    foreach ($document->xpath('//file') ?: [] as $file) {
        $name = relativize((string) $file['name'], $root);

        foreach ($file->line as $line) {
            if ((string) $line['type'] !== 'stmt') {
                continue;
            }

            $map[$name][(int) $line['num']] = (int) $line['count'];
        }
    }

    return $map;
}

/**
 * Read a `path:line` executed set.
 *
 * @return array<string, array<int, true>>
 */
function readLineSet(string $path): array
{
    if (! is_file($path)) {
        fail("Line set not found: {$path}");
    }

    $set = [];

    foreach (file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $entry) {
        $entry = trim($entry);

        if ($entry === '' || str_starts_with($entry, '#')) {
            continue;
        }

        if (! preg_match('/^(.*):(\d+)$/', $entry, $matches)) {
            fail("Malformed line-set entry: {$entry}");
        }

        $set[$matches[1]][(int) $matches[2]] = true;
    }

    return $set;
}

/**
 * Union the nonzero (file, line) pairs of every supplied map.
 *
 * @param  list<array<string, array<int, int>>>  $maps
 * @param  array<string, array<int, true>>  $seed
 * @return array<string, array<int, true>>
 */
function unionExecuted(array $maps, array $seed = []): array
{
    $union = $seed;

    foreach ($maps as $map) {
        foreach ($map as $file => $lines) {
            foreach ($lines as $number => $hits) {
                if ($hits > 0) {
                    $union[$file][$number] = true;
                }
            }
        }
    }

    return $union;
}

/**
 * Parse survivor rows out of a de-ANSI'd non-compact mutation log.
 *
 * Identity is (file, mutator, expression); the plugin's mutation ID is carried
 * alongside as the tool-level key. Rows are returned in log order.
 *
 * @return list<array{state: string, file: string, line: int, mutator: string, id: ?string}>
 */
function readLog(string $path): array
{
    if (! is_file($path)) {
        fail("Mutation log not found: {$path}");
    }

    $rows = [];
    $contents = (string) file_get_contents($path);

    // Defensive: the log is expected to be de-ANSI'd already, but stripping
    // again is harmless and keeps a forgotten `sed` from silently yielding
    // zero rows, which would read as a clean chunk.
    $contents = (string) preg_replace('/\x1b\[[0-9;]*m/', '', $contents);

    // Timed-out mutants never reach the labelled summary block: the plugin's
    // writeMutationTestSummary() returns early for anything that is not
    // Untested or Uncovered. All a timeout leaves behind is a `t Line N:
    // Mutator` glyph row under the current RUN heading, with no path and no
    // mutation ID. Track the heading so those rows can still be attributed.
    $currentFile = null;

    foreach (explode("\n", $contents) as $line) {
        if (preg_match('/^\s*RUN\s+(\S+\.php)\s*$/', $line, $heading) === 1) {
            $currentFile = ltrim($heading[1], './');

            continue;
        }

        if (preg_match('/^\s*t\s+Line\s+(\d+):\s+(\S+)\s*$/', $line, $glyph) === 1) {
            if ($currentFile === null) {
                fwrite(STDERR, "Timeout row before any RUN heading; cannot attribute: {$line}" . PHP_EOL);

                continue;
            }

            $rows[] = [
                'state' => 'TIMEOUT',
                'file' => $currentFile,
                'line' => (int) $glyph[1],
                'mutator' => $glyph[2],
                'id' => null,
            ];

            continue;
        }

        if (! preg_match('/^\s*(UNCOVERED|UNTESTED)\s+(\S+\.php)\s+> Line (\d+): (\S+?)(?:\s+- ID: (\S+))?\s*$/', $line, $matches)) {
            continue;
        }

        $rows[] = [
            'state' => $matches[1],
            'file' => ltrim($matches[2], './'),
            'line' => (int) $matches[3],
            'mutator' => $matches[4],
            'id' => $matches[5] ?? null,
        ];
    }

    return $rows;
}

/**
 * Read the source expression a row sits on, so the row carries its own
 * identity rather than a line number that drifts with the next edit.
 */
function readExpression(string $file, int $line, string $root): ?string
{
    $path = $root . '/' . $file;

    if (! is_file($path)) {
        return null;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES);

    if ($lines === false || ! isset($lines[$line - 1])) {
        return null;
    }

    return trim($lines[$line - 1]);
}

/**
 * Describe what the measuring map says about a row's line, independent of any
 * verdict: `absent` (not an executable statement), `zero`, or `hits`.
 *
 * @param  array<string, array<int, int>>|null  $measuring
 */
function coverageOf(array $row, ?array $measuring): string
{
    if ($measuring === null) {
        return 'unmapped';
    }

    if (! isset($measuring[$row['file']][$row['line']])) {
        return 'absent';
    }

    return $measuring[$row['file']][$row['line']] > 0 ? 'hits' : 'zero';
}

/**
 * @param  array<string, array<int, int>>|null  $measuring
 * @param  array<string, array<int, true>>  $executedElsewhere
 * @return array{disposition: string, coverage: string, contested: bool}
 */
function disposition(array $row, ?array $measuring, array $executedElsewhere): array
{
    $file = $row['file'];
    $line = $row['line'];
    $executed = isset($executedElsewhere[$file][$line]);
    $coverage = coverageOf($row, $measuring);

    // A timeout means a test ran and did not finish. The ledger requires it to
    // be resolved by rerun under recorded conditions, never folded into a kill
    // or a survivor.
    if ($row['state'] === 'TIMEOUT') {
        return ['disposition' => 'timeout-unresolved', 'coverage' => $coverage, 'contested' => false];
    }

    // UNTESTED is direct positive evidence: the plugin routed a test to this
    // mutant and the mutant lived. Line coverage cannot demote that. Mutants
    // on default parameter values sit on a signature line, which is never an
    // executable statement, so the coverage map calls them absent while the
    // plugin correctly reports a survivor. Where the two disagree, the
    // stronger evidence wins and the disagreement is surfaced, not silently
    // resolved.
    if ($row['state'] === 'UNTESTED') {
        return [
            'disposition' => 'executed-and-survived',
            'coverage' => $coverage,
            'contested' => $coverage !== 'hits',
        ];
    }

    if ($measuring === null) {
        // Only an executed set was supplied. Absent-from-set collapses
        // unroutable and never-executed together; say so rather than guess.
        return [
            'disposition' => $executed ? 'executed-and-survived' : 'indeterminate',
            'coverage' => $coverage,
            'contested' => false,
        ];
    }

    if ($coverage === 'absent') {
        // Identical source should yield identical executable lines on every
        // engine. Presence elsewhere means the maps disagree about what is
        // executable, which is a harness problem, not a row disposition.
        return [
            'disposition' => $executed ? 'inconsistent-map' : 'instrument-unroutable',
            'coverage' => $coverage,
            'contested' => false,
        ];
    }

    if ($coverage === 'hits') {
        return ['disposition' => 'executed-and-survived', 'coverage' => $coverage, 'contested' => false];
    }

    return [
        'disposition' => $executed ? 'engine-gated' : 'never-executed',
        'coverage' => $coverage,
        'contested' => false,
    ];
}

/**
 * @param array{file: string, line: int, mutator: string} $row
 */
function rowIdentity(array $row, string $mode = 'line'): string
{
    if ($mode === 'expression') {
        return $row['file'] . ':' . $row['mutator'] . ':' . ($row['expression'] ?? '');
    }

    return $row['file'] . ':' . $row['line'] . ':' . $row['mutator'];
}

/**
 * Build identities without collapsing duplicate rows. The ordinal is stable
 * for the plugin's log order and preserves repeated mutations that share a
 * file/line/mutator key (or repeated expressions in expression mode).
 *
 * @param list<array<string, mixed>> $rows
 * @return array<string, array<string, mixed>>
 */
function keyedRows(array $rows, string $mode): array
{
    $keyed = [];
    $occurrences = [];

    foreach ($rows as $row) {
        $base = rowIdentity($row, $mode);
        $ordinal = $occurrences[$base] ?? 0;
        $occurrences[$base] = $ordinal + 1;
        $keyed[$base . ':' . $ordinal] = $row;
    }

    return $keyed;
}

/**
 * @return array{added: list<array<string, mixed>>, removed: list<array<string, mixed>>}
 */
function baselineDiff(string $path, array $classified, string $identityMode = 'line'): array
{
    if (! is_file($path)) {
        fail("Baseline classification not found: {$path}");
    }

    $decoded = json_decode((string) file_get_contents($path), true);

    if (! is_array($decoded)) {
        fail("Baseline classification is not valid JSON: {$path}");
    }

    // A classification produced with --baseline is wrapped so it can carry
    // its diff. Accept both that form and the original bare row list.
    if (array_key_exists('rows', $decoded) && is_array($decoded['rows'])) {
        $decoded = $decoded['rows'];
    }

    $baselineRows = [];

    foreach ($decoded as $row) {
        if (! is_array($row) || ! isset($row['file'], $row['line'], $row['mutator'])) {
            fail("Baseline classification has an invalid row: {$path}");
        }

        $baselineRows[] = $row;
    }

    $baselineRows = keyedRows($baselineRows, $identityMode);
    $currentRows = keyedRows($classified, $identityMode);

    $added = [];

    foreach ($currentRows as $identity => $row) {
        if (! array_key_exists($identity, $baselineRows)) {
            $added[] = $row;
        }
    }

    $removed = [];

    foreach ($baselineRows as $identity => $row) {
        if (! array_key_exists($identity, $currentRows)) {
            $removed[] = $row;
        }
    }

    return ['added' => $added, 'removed' => $removed];
}

$options = parseArguments($argv);
$root = $options['root'];

$measuring = $options['map'] !== null ? readClover($options['map'], $root) : null;
$unionMaps = array_map(static fn (string $path): array => readClover($path, $root), $options['union']);
$seed = $options['lines'] !== null ? readLineSet($options['lines']) : [];

// The union deliberately excludes the measuring map: a row is engine-gated
// only when another engine executes what this one could not.
$executedElsewhere = unionExecuted($unionMaps, $seed);

if ($options['emit'] !== null) {
    $emitted = unionExecuted($measuring !== null ? [$measuring, ...$unionMaps] : $unionMaps, $seed);
    $entries = [];

    foreach ($emitted as $file => $lines) {
        foreach (array_keys($lines) as $number) {
            $entries[] = $file . ':' . $number;
        }
    }

    sort($entries);
    file_put_contents($options['emit'], implode(PHP_EOL, $entries) . PHP_EOL);
}

$classified = [];

foreach (readLog($options['log']) as $row) {
    $row['expression'] = readExpression($row['file'], $row['line'], $root);
    $classified[] = [...$row, ...disposition($row, $measuring, $executedElsewhere)];
}

$diff = $options['baseline'] !== null
    ? baselineDiff($options['baseline'], $classified, $options['baselineIdentity'])
    : null;

if ($options['json']) {
    $output = $diff === null
        ? $classified
        : ['rows' => $classified, 'baseline_diff' => $diff];

    echo json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;

    exit(hasInconsistency($classified) ? 2 : 0);
}

if ($diff !== null) {
    printf("BASELINE ADDED (%d)\n", count($diff['added']));

    foreach ($diff['added'] as $row) {
        printf("  %s\n", rowIdentity($row));
    }

    printf("BASELINE REMOVED (%d)\n", count($diff['removed']));

    foreach ($diff['removed'] as $row) {
        printf("  %s\n", rowIdentity($row));
    }
}

function hasInconsistency(array $classified): bool
{
    foreach ($classified as $row) {
        if ($row['disposition'] === 'inconsistent-map') {
            return true;
        }
    }

    return false;
}

$buckets = array_fill_keys(DISPOSITIONS, []);

foreach ($classified as $row) {
    $buckets[$row['disposition']][] = $row;
}

foreach ($buckets as $name => $rows) {
    if ($rows === []) {
        continue;
    }

    printf('%s (%d)%s', strtoupper($name), count($rows), PHP_EOL);

    foreach ($rows as $row) {
        printf(
            '  %s:%d  %s  %s  [%s]%s  %s%s',
            $row['file'],
            $row['line'],
            $row['state'],
            $row['mutator'],
            $row['id'] ?? 'no-id',
            $row['contested'] ? '  CONTESTED(coverage=' . $row['coverage'] . ')' : '',
            $row['expression'] ?? '<source unavailable>',
            PHP_EOL
        );
    }

    echo PHP_EOL;
}

$contested = array_values(array_filter($classified, static fn (array $row): bool => $row['contested']));

if ($contested !== []) {
    printf('CONTESTED (%d) — the plugin reports a survivor on a line the map calls %s%s', count($contested), 'non-executable' . PHP_EOL, PHP_EOL);

    foreach ($contested as $row) {
        printf('  %s:%d  %s  %s%s', $row['file'], $row['line'], $row['mutator'], $row['expression'] ?? '', PHP_EOL);
    }

    echo PHP_EOL;
}

printf('%d rows classified.%s', count($classified), PHP_EOL);

exit(hasInconsistency($classified) ? 2 : 0);
