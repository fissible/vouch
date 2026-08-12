<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Fissible\Vouch\Tests\Support\KernelFileWalker;

$root = (string) realpath(__DIR__ . '/../src/Kernel');
$entries = [];

foreach (KernelFileWalker::phpFiles() as $file) {
    $relative = str_replace($root . '/', '', $file->getPathname());
    $class = 'Fissible\\Vouch\\Kernel\\' . str_replace(['/', '.php'], ['\\', ''], $relative);

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
    // zero-method marker interface) must move the snapshot, even though it
    // contributes no method/property/case entries below.
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

echo implode("\n", $entries), "\n";
