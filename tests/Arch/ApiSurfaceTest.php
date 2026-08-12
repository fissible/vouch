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

        $kind = match (true) {
            enum_exists($class) => 'enum',
            interface_exists($class) => 'interface',
            class_exists($class) => 'class',
            default => null,
        };

        if ($kind === null) {
            continue;
        }

        // The type declaration itself is a symbol: deleting `Requirement` (a
        // zero-method marker interface) must move the snapshot, even though
        // it contributes no method/property/case entries below.
        $entries[] = sprintf('%s (%s)', $class, $kind);

        $reflection = new ReflectionClass($class);

        foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
            if ($method->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            $entries[] = sprintf('%s::%s()', $class, $method->getName());
        }

        foreach ($reflection->getProperties(ReflectionProperty::IS_PUBLIC) as $property) {
            if ($property->getDeclaringClass()->getName() !== $class) {
                continue;
            }

            $entries[] = sprintf('%s::$%s', $class, $property->getName());
        }

        if ($kind === 'enum') {
            foreach ((new ReflectionEnum($class))->getCases() as $case) {
                $entries[] = sprintf('%s::%s (case)', $class, $case->getName());
            }
        }
    }

    sort($entries);

    $snapshotPath = __DIR__ . '/../../docs/kernel-api-surface.md';
    $expected = trim((string) file_get_contents($snapshotPath));
    $actual = trim(implode("\n", $entries));

    expect($actual)->toBe(
        $expected,
        "Kernel public API changed — a type, public method, public property, or enum "
        . "case was added, removed, or renamed under src/Kernel. If intentional, "
        . "regenerate with `php bin/kernel-api-surface.php > docs/kernel-api-surface.md`, "
        . "commit the updated snapshot, and note the change — the §8.1 extraction "
        . "trigger requires a full minor cycle with no breaking change to this surface.",
    );
});
