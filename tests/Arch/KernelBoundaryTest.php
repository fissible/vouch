<?php

declare(strict_types=1);

use Fissible\Vouch\Tests\Support\KernelFileWalker;

arch('kernel classes are final')
    ->expect('Fissible\Vouch\Kernel')
    ->classes()
    ->toBeFinal();

// Two Pest `arch()->not->toUse([...])` expectations stood here — one banning the
// framework namespaces, one banning global helpers and global time. Both were
// deleted, because both were structurally incapable of failing, and an
// always-green assertion that reads as enforcement is worse than no assertion at
// all: a maintainer sees "kernel does not depend on any framework" pass and
// believes the boundary is guarded. Empirically established (see
// task-1-report.md), not assumed:
//
// - `toUse()`'s dependency resolution (Pest\Arch\Repositories\ObjectsRepository)
//   only recognises a dependency name as "used" when it matches a directory
//   reachable through this project's *own* registered Composer PSR-4 prefixes.
//   Bare top-level segments like 'Illuminate' or 'Symfony' never match, because
//   real packages register their full namespace root (e.g. 'Symfony\Component\
//   Console\'), never the bare vendor segment — so the framework ban was vacuous
//   then and would remain vacuous after illuminate/* packages arrive in Phase 2.
// - Its use-detection for bare function calls (PHPUnit\Architecture\Asserts\
//   Dependencies\ObjectDependenciesDescription) only counts a call if
//   `function_exists()` is true for that name *right now*. Laravel-style helpers
//   (app, config, now, event, dd, dump) do not exist in this framework-free
//   package, so calls to them were silently invisible to `toUse()`.
//
// The regex source scans below are the real enforcement for both banned lists,
// and for spec §8.1's clock and immutability rules. Their known limits, so a
// reader calibrates trust rather than assuming totality: a name assembled at
// runtime ('Illuminate' . '\\Support') or introduced under an alias
// (`use function time as clock;`) evades them. Both are deliberate
// circumventions rather than accidents, and are out of scope for a denylist.

it('never instantiates a clock directly', function (): void {
    $patterns = [
        // `new DateTimeImmutable;` — no argument list — is valid PHP and reads
        // the system clock, so the parenthesis must be optional. `\b` still
        // excludes `new DateTimeZone(...)`, which carries no clock reading, and
        // the `new\s+` prefix excludes the parameter type hints the kernel
        // legitimately needs.
        '/\bnew\s+\\\\?DateTime(Immutable)?\b/i',
        // Static constructors build an instance without `new`:
        // createFromFormat, createFromInterface, createFromTimestamp,
        // createFromMutable.
        '/\bDateTime(Immutable)?\s*::\s*create/i',
    ];

    $offenders = [];

    foreach (KernelFileWalker::phpFiles() as $file) {
        $source = (string) file_get_contents($file->getPathname());

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $source) === 1) {
                $offenders[] = $file->getPathname() . ' :: ' . $pattern;
            }
        }
    }

    expect($offenders)->toBeEmpty();
});

it('never uses a banned framework namespace', function (): void {
    $bannedNamespaces = ['Illuminate', 'Laravel', 'Filament', 'Livewire', 'Symfony'];
    $offenders = [];

    foreach (KernelFileWalker::phpFiles() as $file) {
        $source = (string) file_get_contents($file->getPathname());

        foreach ($bannedNamespaces as $namespace) {
            // Case-insensitive: PHP namespace segments are case-insensitive, so
            // `use illuminate\support\Facades\Auth;` resolves exactly as the
            // canonical spelling does and must be caught the same way.
            if (preg_match('/\b' . preg_quote($namespace, '/') . '\\\\/i', $source) === 1) {
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

    foreach (KernelFileWalker::phpFiles() as $file) {
        $source = (string) file_get_contents($file->getPathname());

        foreach ($bannedHelpers as $helper) {
            // Excludes method calls (->helper()) and static calls (::helper())
            // by rejecting a match immediately preceded by '>' or ':', so that
            // legitimate calls like $clock->now() are not flagged.
            //
            // Case-insensitive: PHP function names are case-insensitive, so
            // `Date('Y')` is a real call to global date() and must be caught.
            if (preg_match('/(?<![:>])\b' . preg_quote($helper, '/') . '\s*\(/i', $source) === 1) {
                $offenders[] = $file->getPathname() . ' :: ' . $helper . '()';
            }
        }
    }

    expect($offenders)->toBeEmpty();
});

it('declares every kernel class that holds state readonly', function (): void {
    // `toBeFinal()` above checks finality only. Spec §8.1 requires kernel classes
    // holding state to be `final readonly` — "ScreenSpec qualifies for the kernel
    // only while it remains immutable" — and without this a `final class` with a
    // mutable public property passes every other gate here and PHPStan level 9.
    //
    // Pest's own `->toBeReadonly()` was tried first and rejected empirically: it
    // is a blanket check with no notion of state, so it fails on the intentionally
    // stateless `final class` services (NistAssuranceVocabulary, ErrorShaper,
    // SatisfiabilityEvaluator) that spec §8.1 does not require to be readonly.
    // This scan is state-aware: a class with no instance properties is exempt.
    $root = (string) realpath(__DIR__ . '/../../src/Kernel');
    $offenders = [];

    foreach (KernelFileWalker::phpFiles() as $file) {
        $relative = str_replace($root . '/', '', $file->getPathname());
        $class = 'Fissible\\Vouch\\Kernel\\'
            . str_replace(['/', '.php'], ['\\', ''], $relative);

        // Interfaces hold no state. Enums cannot be declared readonly and cannot
        // carry mutable instance state either — their `name`/`value` are
        // implicitly readonly — so neither may produce a false failure here.
        if (! class_exists($class) || enum_exists($class)) {
            continue;
        }

        $reflection = new ReflectionClass($class);

        $instanceProperties = array_filter(
            $reflection->getProperties(),
            static fn (ReflectionProperty $property): bool => ! $property->isStatic(),
        );

        if ($instanceProperties === []) {
            continue;
        }

        if (! $reflection->isReadOnly()) {
            $offenders[] = $class . ' holds instance state but is not declared readonly';
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});
