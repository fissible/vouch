<?php

declare(strict_types=1);

/**
 * Extract a stable mutation-survivor manifest from pest-plugin-mutate output.
 *
 * Mutation IDs and line numbers drift when unrelated source moves. Review units
 * therefore use (file, mutator, expression), with the expression read from the
 * exact source tree against which the run completed. Timeout identities are not
 * repeated in the plugin's detailed section, so they are recovered from the
 * per-file progress stream instead.
 */

if ($argc < 2 || $argc > 3) {
    fwrite(STDERR, "Usage: php bin/mutation-survivors.php <mutation-log> [source-root]\n");

    exit(64);
}

$logPath = $argv[1];
$sourceRoot = rtrim($argv[2] ?? dirname(__DIR__), DIRECTORY_SEPARATOR);
$contents = file_get_contents($logPath);

if ($contents === false) {
    fwrite(STDERR, sprintf("Unable to read mutation log: %s\n", $logPath));

    exit(66);
}

$lines = preg_split('/\R/', $contents);

if (!is_array($lines)) {
    fwrite(STDERR, "Unable to split mutation log.\n");

    exit(65);
}

/** @var array<string, list<string>> $sourceLines */
$sourceLines = [];

$expressionAt = static function (string $file, int $line) use ($sourceRoot, &$sourceLines): string {
    if (!isset($sourceLines[$file])) {
        $path = $sourceRoot . DIRECTORY_SEPARATOR . $file;
        $loaded = file($path, FILE_IGNORE_NEW_LINES);

        if ($loaded === false) {
            throw new RuntimeException(sprintf('Unable to read source file %s.', $path));
        }

        $sourceLines[$file] = $loaded;
    }

    $target = $line - 1;

    if (!isset($sourceLines[$file][$target])) {
        throw new RuntimeException(sprintf('Source line %s:%d does not exist.', $file, $line));
    }

    $start = $target;

    while ($start > 0) {
        $previous = trim($sourceLines[$file][$start - 1]);

        if ($previous === '' || preg_match('/[;{}:]$/', $previous) === 1) {
            break;
        }

        $start--;
    }

    $end = $target;

    while (isset($sourceLines[$file][$end + 1]) && preg_match('/[;{}]$/', trim($sourceLines[$file][$end])) !== 1) {
        $end++;
    }

    $parts = [];

    for ($index = $start; $index <= $end; $index++) {
        $part = trim($sourceLines[$file][$index]);

        if ($part === '' || preg_match('#^(//|/\*|\*|\*/)#', $part) === 1) {
            continue;
        }

        $parts[] = $part;
    }

    return preg_replace('/\s+/', ' ', implode(' ', $parts)) ?? implode(' ', $parts);
};

/** @var list<array{result: string, file: string, line: int, mutator: string, id: ?string, expression: string}> $rows */
$rows = [];
/** @var array<string, true> $runFiles */
$runFiles = [];
$currentRunFile = null;

foreach ($lines as $line) {
    if (preg_match('/^\s*RUN\s+(src\/\S+\.php)\s*$/', $line, $matches) === 1) {
        $currentRunFile = $matches[1];
        $runFiles[$currentRunFile] = true;

        continue;
    }

    if (preg_match('/^\s*(UNTESTED|UNCOVERED)\s+(src\/\S+\.php)\s+>\s+Line\s+(\d+):\s+(\S+)\s+-\s+ID:\s+([a-f0-9]+)\s*$/', $line, $matches) === 1) {
        $lineNumber = (int) $matches[3];
        $rows[] = [
            'result' => $matches[1],
            'file' => $matches[2],
            'line' => $lineNumber,
            'mutator' => $matches[4],
            'id' => $matches[5],
            'expression' => $expressionAt($matches[2], $lineNumber),
        ];

        continue;
    }

    if ($currentRunFile !== null && preg_match('/^\s*t\s+Line\s+(\d+):\s+(\S+)\s*$/', $line, $matches) === 1) {
        $lineNumber = (int) $matches[1];
        $rows[] = [
            'result' => 'TIMEOUT',
            'file' => $currentRunFile,
            'line' => $lineNumber,
            'mutator' => $matches[2],
            'id' => null,
            'expression' => $expressionAt($currentRunFile, $lineNumber),
        ];
    }
}

usort($rows, static fn(array $left, array $right): int => [
    $left['file'],
    $left['line'],
    $left['mutator'],
    $left['id'] ?? '',
] <=> [
    $right['file'],
    $right['line'],
    $right['mutator'],
    $right['id'] ?? '',
]);

/** @var array<string, array{file: string, mutator: string, expression: string, rows: int, results: array<string, int>, lines: list<int>, ids: list<string>}> $groups */
$groups = [];

foreach ($rows as $row) {
    $key = implode("\0", [$row['file'], $row['mutator'], $row['expression']]);
    $groups[$key] ??= [
        'file' => $row['file'],
        'mutator' => $row['mutator'],
        'expression' => $row['expression'],
        'rows' => 0,
        'results' => [],
        'lines' => [],
        'ids' => [],
    ];
    $groups[$key]['rows']++;
    $groups[$key]['results'][$row['result']] = ($groups[$key]['results'][$row['result']] ?? 0) + 1;
    $groups[$key]['lines'][] = $row['line'];

    if ($row['id'] !== null) {
        $groups[$key]['ids'][] = $row['id'];
    }
}

foreach ($groups as &$group) {
    $group['lines'] = array_values(array_unique($group['lines']));
    sort($group['lines']);
    sort($group['ids']);
    ksort($group['results']);
}
unset($group);

uasort($groups, static fn(array $left, array $right): int => [
    $left['file'],
    $left['mutator'],
    $left['expression'],
] <=> [
    $right['file'],
    $right['mutator'],
    $right['expression'],
]);

$headline = null;
$created = null;

if (preg_match('/Mutations:\s+(\d+) untested,\s+(\d+) uncovered,\s+(\d+) timeout,\s+(\d+) tested/', $contents, $matches) === 1) {
    $headline = [
        'untested' => (int) $matches[1],
        'uncovered' => (int) $matches[2],
        'timeout' => (int) $matches[3],
        'tested' => (int) $matches[4],
    ];
}

if (preg_match('/(\d+) Mutations for (\d+) Files created/', $contents, $matches) === 1) {
    $created = [
        'mutations' => (int) $matches[1],
        'files' => (int) $matches[2],
    ];
}

$payload = [
    'log' => $logPath,
    'sha256' => hash('sha256', $contents),
    'integrity' => [
        'created' => $created,
        'headline' => $headline,
        'run_files' => count($runFiles),
        'fatal_errors' => preg_match_all('/Fatal error/', $contents),
        'no_tests_found' => preg_match_all('/No tests found/', $contents),
        'kernel_rows' => preg_match_all('/src\/Kernel\//', $contents),
        'extracted_rows' => count($rows),
        'groups' => count($groups),
    ],
    'run_files' => array_keys($runFiles),
    'groups' => array_values($groups),
    'rows' => $rows,
];

echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
