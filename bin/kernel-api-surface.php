<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Fissible\Vouch\Tests\Support\KernelFileWalker;

$root = (string) realpath(__DIR__ . '/../src/Kernel');
$entries = [];

foreach (KernelFileWalker::phpFiles() as $file) {
    $relative = str_replace($root . '/', '', $file->getPathname());
    $class = 'Fissible\\Vouch\\Kernel\\' . str_replace(['/', '.php'], ['\\', ''], $relative);

    if (! class_exists($class) && ! interface_exists($class) && ! enum_exists($class)) {
        continue;
    }

    foreach ((new ReflectionClass($class))->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
        if ($method->getDeclaringClass()->getName() !== $class) {
            continue;
        }

        $entries[] = sprintf('%s::%s', $class, $method->getName());
    }
}

sort($entries);

echo implode("\n", $entries), "\n";
