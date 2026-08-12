<?php

declare(strict_types=1);

use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

arch('kernel does not depend on any framework')
    ->expect('Fissible\Vouch\Kernel')
    ->not->toUse([
        'Illuminate',
        'Laravel',
        'Filament',
        'Livewire',
        'Symfony',
    ]);

arch('kernel does not call global helpers or global time')
    ->expect('Fissible\Vouch\Kernel')
    ->not->toUse([
        'app',
        'config',
        'now',
        'event',
        'dd',
        'dump',
        'time',
        'date',
        'microtime',
        'mktime',
        'strtotime',
    ]);

arch('kernel classes are final')
    ->expect('Fissible\Vouch\Kernel')
    ->classes()
    ->toBeFinal();

it('never instantiates a clock directly', function (): void {
    $offenders = [];

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(__DIR__ . '/../../src/Kernel'),
    );

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $source = (string) file_get_contents($file->getPathname());

        if (preg_match('/\bnew\s+\\\\?DateTime(Immutable)?\s*\(/', $source) === 1) {
            $offenders[] = $file->getPathname();
        }
    }

    expect($offenders)->toBeEmpty();
});

// The two `toUse()` arch expectations above are declared for documentation
// value, but neither is actually enforced by Pest in this package, and both
// were proven empirically (see task-1-report.md) rather than assumed:
//
// - `toUse()`'s dependency resolution (Pest\Arch\Repositories\ObjectsRepository)
//   only recognises a dependency name as "used" when it matches a directory
//   reachable through this project's *own* registered Composer PSR-4 prefixes.
//   Bare top-level segments like 'Illuminate' or 'Symfony' never match, because
//   real packages register their full namespace root (e.g. 'Symfony\Component\
//   Console\'), never the bare vendor segment — so the framework-ban expectation
//   is vacuous today and will remain vacuous even after illuminate/* packages
//   are added in Phase 2.
// - Its "use detection" for bare function calls (PHPUnit\Architecture\Asserts\
//   Dependencies\ObjectDependenciesDescription) only counts a call if
//   `function_exists()` is true for that name *right now*. Native PHP functions
//   (time, date, microtime, mktime, strtotime) pass; Laravel-style helpers
//   (app, config, now, event, dd, dump) don't exist in this framework-free
//   package, so calls to them are silently invisible to `toUse()`.
//
// The two scans below are the actual enforcement mechanism for both banned
// lists, by regex over src/Kernel/**.php, mirroring the clock-instantiation
// scan above.

it('never uses a banned framework namespace', function (): void {
    $bannedNamespaces = ['Illuminate', 'Laravel', 'Filament', 'Livewire', 'Symfony'];
    $offenders = [];

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(__DIR__ . '/../../src/Kernel'),
    );

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $source = (string) file_get_contents($file->getPathname());

        foreach ($bannedNamespaces as $namespace) {
            if (preg_match('/\b' . preg_quote($namespace, '/') . '\\\\/', $source) === 1) {
                $offenders[] = $file->getPathname() . ' :: ' . $namespace;
            }
        }
    }

    expect($offenders)->toBeEmpty();
});

it('never calls a banned global helper or global time function', function (): void {
    $bannedHelpers = [
        'app', 'config', 'now', 'event', 'dd', 'dump',
        'time', 'date', 'microtime', 'mktime', 'strtotime',
    ];
    $offenders = [];

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(__DIR__ . '/../../src/Kernel'),
    );

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $source = (string) file_get_contents($file->getPathname());

        foreach ($bannedHelpers as $helper) {
            // Excludes method calls (->helper()) and static calls (::helper())
            // by rejecting a match immediately preceded by '>' or ':', so that
            // legitimate calls like $clock->now() are not flagged.
            if (preg_match('/(?<![:>])\b' . preg_quote($helper, '/') . '\s*\(/', $source) === 1) {
                $offenders[] = $file->getPathname() . ' :: ' . $helper . '()';
            }
        }
    }

    expect($offenders)->toBeEmpty();
});
