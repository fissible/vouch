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
 *                          [--emit-lines=FILE] [--json]
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
 *   --json         emit rows as JSON instead of a grouped report.
 *
 * Exit codes: 0 classified, 1 usage error, 2 map inconsistency detected.
 */

const DISPOSITIONS = [
    'instrument-unroutable',
    'never-executed',
    'engine-gated',
    'executed-and-survived',
    'indeterminate',
    'inconsistent-map',
];

/**
 * @return array{log: string, map: ?string, union: list<string>, lines: ?string,
 *               root: string, emit: ?string, json: bool}
 */
function parseArguments(array $argv): array
{
    $options = ['log' => null, 'map' => null, 'union' => [], 'lines' => null,
        'root' => getcwd(), 'emit' => null, 'json' => false];

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
            default => fail("Unrecognized option: --{$name}"),
        };
    }

    if ($options['log'] === null) {
        fail('--log is required.');
    }

    if ($options['map'] === null && $options['lines'] === null) {
        fail('Either --map or --lines is required.');
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

    foreach (explode("\n", $contents) as $line) {
        if (! preg_match('/^\s*(UNCOVERED|UNTESTED|TIMEOUT)\s+(\S+\.php)\s+> Line (\d+): (\S+?)(?:\s+- ID: (\S+))?\s*$/', $line, $matches)) {
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
 * @param  array<string, array<int, int>>|null  $measuring
 * @param  array<string, array<int, true>>  $executedElsewhere
 */
function disposition(array $row, ?array $measuring, array $executedElsewhere): string
{
    $file = $row['file'];
    $line = $row['line'];
    $executed = isset($executedElsewhere[$file][$line]);

    if ($measuring === null) {
        // Only an executed set was supplied. Absent-from-set collapses
        // unroutable and never-executed together; say so rather than guess.
        return $executed ? 'executed-and-survived' : 'indeterminate';
    }

    if (! isset($measuring[$file][$line])) {
        // Identical source should yield identical executable lines on every
        // engine. Presence elsewhere means the maps disagree about what is
        // executable, which is a harness problem, not a row disposition.
        return $executed ? 'inconsistent-map' : 'instrument-unroutable';
    }

    if ($measuring[$file][$line] > 0) {
        return 'executed-and-survived';
    }

    return $executed ? 'engine-gated' : 'never-executed';
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
    $row['disposition'] = disposition($row, $measuring, $executedElsewhere);
    $classified[] = $row;
}

if ($options['json']) {
    echo json_encode($classified, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), PHP_EOL;

    exit(hasInconsistency($classified) ? 2 : 0);
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
            '  %s:%d  %s  %s  [%s]  %s%s',
            $row['file'],
            $row['line'],
            $row['state'],
            $row['mutator'],
            $row['id'] ?? 'no-id',
            $row['expression'] ?? '<source unavailable>',
            PHP_EOL
        );
    }

    echo PHP_EOL;
}

printf('%d rows classified.%s', count($classified), PHP_EOL);

exit(hasInconsistency($classified) ? 2 : 0);
