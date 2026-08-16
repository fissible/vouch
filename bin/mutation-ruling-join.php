<?php

declare(strict_types=1);

/**
 * Join mutation-survivor JSON to explicit review-unit tables.
 *
 * Input is the JSON emitted by bin/mutation-survivors.php. Each Markdown input
 * must contain rows with the manifest shape:
 *
 * | rows | `file` | Mutator | `expression` | `ruling document` |
 *
 * A historical expression may be a truncated prefix. Whitespace is ignored for
 * matching because the original manifest collapsed multiline statements, while
 * string and operator content remains part of the identity.
 */

if ($argc < 2) {
    fwrite(STDERR, "Usage: php bin/mutation-ruling-join.php <rulings.md> [...] < survivors.json\n");

    exit(64);
}

$input = stream_get_contents(STDIN);

if ($input === false) {
    fwrite(STDERR, "Unable to read survivor JSON from stdin.\n");

    exit(65);
}

/** @var array{groups?: list<array<string, mixed>>} $manifest */
$manifest = json_decode($input, true, flags: JSON_THROW_ON_ERROR);
$groups = $manifest['groups'] ?? null;

if (!is_array($groups)) {
    fwrite(STDERR, "Survivor JSON has no groups array.\n");

    exit(65);
}

$canonical = static function (string $expression): string {
    $expression = str_replace(['\\|', '\\`'], ['|', '`'], $expression);

    return preg_replace('/\s+/', '', $expression) ?? $expression;
};

/** @var list<array{file: string, mutator: string, expression: string, document: string}> $claims */
$claims = [];

foreach (array_slice($argv, 1) as $path) {
    $contents = file_get_contents($path);

    if ($contents === false) {
        fwrite(STDERR, sprintf("Unable to read ruling document: %s\n", $path));

        exit(66);
    }

    foreach (preg_split('/\R/', $contents) ?: [] as $line) {
        if (preg_match('/^\|\s*\d+\s*\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|\s*`(.+)`\s*\|\s*`([^`]+)`\s*\|$/', $line, $matches) !== 1) {
            continue;
        }

        $claims[] = [
            'file' => $matches[1],
            'mutator' => trim($matches[2]),
            'expression' => $canonical($matches[3]),
            'document' => $matches[4],
        ];
    }
}

$unruled = [];
$doubleClaimed = [];
$assignedRows = 0;

foreach ($groups as &$group) {
    $expression = $canonical((string) $group['expression']);
    $matches = [];

    foreach ($claims as $claim) {
        if ($claim['file'] !== $group['file'] || $claim['mutator'] !== $group['mutator']) {
            continue;
        }

        if (str_starts_with($expression, $claim['expression'])) {
            $matches[$claim['document']] = true;
        }
    }

    $group['rulings'] = array_keys($matches);

    if ($group['rulings'] === []) {
        $unruled[] = $group;
    } elseif (count($group['rulings']) > 1) {
        $doubleClaimed[] = $group;
    } else {
        $assignedRows += (int) $group['rows'];
    }
}
unset($group);

$manifest['groups'] = $groups;
$manifest['join'] = [
    'claims' => count($claims),
    'assigned_rows' => $assignedRows,
    'unruled_groups' => count($unruled),
    'unruled_rows' => array_sum(array_map(static fn(array $group): int => (int) $group['rows'], $unruled)),
    'double_claimed_groups' => count($doubleClaimed),
    'double_claimed_rows' => array_sum(array_map(static fn(array $group): int => (int) $group['rows'], $doubleClaimed)),
];

echo json_encode($manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
