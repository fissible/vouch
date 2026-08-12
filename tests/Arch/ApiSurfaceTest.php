<?php

declare(strict_types=1);

use Fissible\Vouch\Tests\Support\KernelFileWalker;

it('matches the committed public API surface', function (): void {
    $root = (string) realpath(__DIR__ . '/../../src/Kernel');
    $entries = [];

    foreach (KernelFileWalker::phpFiles() as $file) {
        $relative = str_replace($root . '/', '', $file->getPathname());
        $class = 'Fissible\\Vouch\\Kernel\\'
            . str_replace(['/', '.php'], ['\\', ''], $relative);

        if (! class_exists($class) && ! interface_exists($class) && ! enum_exists($class)) {
            continue;
        }

        $reflection = new ReflectionClass($class);

        foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            $entries[] = sprintf('%s::%s', $class, $method->getName());
        }
    }

    sort($entries);

    $snapshotPath = __DIR__ . '/../../docs/kernel-api-surface.md';
    $expected = trim((string) file_get_contents($snapshotPath));
    $actual = trim(implode("\n", $entries));

    expect($actual)->toBe(
        $expected,
        "Kernel public API changed. If intentional, update docs/kernel-api-surface.md "
        . "and note the change — the §8.1 extraction trigger requires a full minor "
        . "cycle with no breaking change to this surface.",
    );
});
