<?php

declare(strict_types=1);

use Symfony\Component\Process\Process;

/**
 * @return array{
 *     integrity: array<array-key, mixed>,
 *     groups: list<array<array-key, mixed>>,
 *     join?: array<array-key, mixed>
 * }
 */
function mutationManifestFromJson(string $json): array
{
    $decoded = json_decode($json, true, flags: JSON_THROW_ON_ERROR);

    if (! is_array($decoded)) {
        throw new RuntimeException('Mutation manifest JSON is not an object.');
    }

    $integrity = $decoded['integrity'] ?? null;
    $groups = $decoded['groups'] ?? null;

    if (! is_array($integrity) || ! is_array($groups)) {
        throw new RuntimeException('Mutation manifest JSON has no integrity or groups object.');
    }

    $normalizedGroups = [];

    foreach ($groups as $group) {
        if (! is_array($group)) {
            throw new RuntimeException('Mutation manifest group is not an object.');
        }

        $normalizedGroups[] = $group;
    }

    $manifest = ['integrity' => $integrity, 'groups' => $normalizedGroups];
    $join = $decoded['join'] ?? null;

    if ($join !== null) {
        if (! is_array($join)) {
            throw new RuntimeException('Mutation manifest join is not an object.');
        }

        $manifest['join'] = $join;
    }

    return $manifest;
}

/** @return array{root: string, log: string} */
function mutationExtractorFixture(): array
{
    $root = sys_get_temp_dir() . '/vouch-mutation-extractor-' . bin2hex(random_bytes(8));
    $source = $root . '/src/Demo.php';
    $log = $root . '/mutation.log';

    mkdir($root . '/src', recursive: true);
    file_put_contents($source, <<<'PHP'
<?php

if ($enabled) {
    return 1;
}
PHP);
    file_put_contents($log, <<<'LOG'
  2 Mutations for 1 Files created
   RUN  src/Demo.php
  ⨯ Line 3: IfNegated
  t Line 4: IncrementInteger

   UNTESTED  src/Demo.php  > Line 3: IfNegated - ID: abcdef0123456789

  -if ($enabled) {
  +if (! $enabled) {

  Mutations: 1 untested, 0 uncovered, 1 timeout, 0 tested
LOG);

    return ['root' => $root, 'log' => $log];
}

function removeMutationExtractorFixture(string $root): void
{
    foreach ([$root . '/src/Demo.php', $root . '/mutation.log'] as $file) {
        if (is_file($file)) {
            unlink($file);
        }
    }

    if (is_dir($root . '/src')) {
        rmdir($root . '/src');
    }

    if (is_dir($root)) {
        rmdir($root);
    }
}

it('extracts survivors and timeouts into stable expression groups', function (): void {
    $fixture = mutationExtractorFixture();

    try {
        $process = new Process([
            PHP_BINARY,
            __DIR__ . '/../../bin/mutation-survivors.php',
            $fixture['log'],
            $fixture['root'],
        ]);
        $process->mustRun();

        $manifest = mutationManifestFromJson($process->getOutput());

        expect($manifest['integrity'])->toMatchArray([
            'created' => ['mutations' => 2, 'files' => 1],
            'headline' => ['untested' => 1, 'uncovered' => 0, 'timeout' => 1, 'tested' => 0],
            'run_files' => 1,
            'fatal_errors' => 0,
            'no_tests_found' => 0,
            'kernel_rows' => 0,
            'extracted_rows' => 2,
            'groups' => 2,
        ])->and($manifest['groups'][0])->toMatchArray([
            'file' => 'src/Demo.php',
            'mutator' => 'IfNegated',
            'expression' => 'if ($enabled) {',
            'rows' => 1,
            'results' => ['UNTESTED' => 1],
        ])->and($manifest['groups'][1])->toMatchArray([
            'file' => 'src/Demo.php',
            'mutator' => 'IncrementInteger',
            'expression' => 'return 1;',
            'rows' => 1,
            'results' => ['TIMEOUT' => 1],
        ]);
    } finally {
        removeMutationExtractorFixture($fixture['root']);
    }
});

it('joins only explicit file mutator and expression correspondence', function (): void {
    $fixture = mutationExtractorFixture();
    $rulings = $fixture['root'] . '/rulings.md';

    try {
        $extract = new Process([
            PHP_BINARY,
            __DIR__ . '/../../bin/mutation-survivors.php',
            $fixture['log'],
            $fixture['root'],
        ]);
        $extract->mustRun();

        file_put_contents($rulings, <<<'MD'
| rows | file | mutator | expression | ruling document |
|---|---|---|---|---|
| 1 | `src/Demo.php` | IfNegated | `if ($enabled) {` | `demo-rulings` |
MD);

        $join = new Process([
            PHP_BINARY,
            __DIR__ . '/../../bin/mutation-ruling-join.php',
            $rulings,
        ]);
        $join->setInput($extract->getOutput());
        $join->mustRun();

        $manifest = mutationManifestFromJson($join->getOutput());

        if (! isset($manifest['join'])) {
            throw new RuntimeException('Joined mutation manifest has no join result.');
        }

        expect($manifest['join'])->toBe([
            'claims' => 1,
            'assigned_rows' => 1,
            'unruled_groups' => 1,
            'unruled_rows' => 1,
            'double_claimed_groups' => 0,
            'double_claimed_rows' => 0,
        ])->and($manifest['groups'][0]['rulings'])->toBe(['demo-rulings'])
            ->and($manifest['groups'][1]['rulings'])->toBe([]);
    } finally {
        if (is_file($rulings)) {
            unlink($rulings);
        }

        removeMutationExtractorFixture($fixture['root']);
    }
});
