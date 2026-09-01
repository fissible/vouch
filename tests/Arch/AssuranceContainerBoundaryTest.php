<?php

declare(strict_types=1);

/*
 * Issue #10 — the assurance value objects must not reach the container.
 *
 * The deletion of derivedAcr() is the fix; this file is the part that lasts.
 * The pressure that produced the ambient call is permanent — someone needs a
 * level name somewhere no vocabulary is in scope, and app() is one line — so
 * without a guard the same shortcut returns under a different method name.
 *
 * Regex source scanning rather than Pest's toUse(): KernelBoundaryTest records
 * why toUse() cannot see calls to global helpers that do not exist in a
 * framework-free package, and the same limitation applies to app() here.
 */

/** @return list<string> */
function assuranceValueObjectFiles(): array
{
    $files = glob(__DIR__ . '/../../src/Assurance/*.php');

    if ($files === false || $files === []) {
        throw new RuntimeException('No assurance value objects found to scan.');
    }

    return $files;
}

/** @return list<string> */
function shippedPhpFiles(): array
{
    $found = [];
    $directory = new RecursiveDirectoryIterator(__DIR__ . '/../../src');
    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator($directory) as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $found[] = $file->getPathname();
        }
    }

    if ($found === []) {
        throw new RuntimeException('No shipped PHP files found to scan.');
    }

    return $found;
}

it('never resolves a dependency out of the container in an assurance value object', function (): void {
    $patterns = [
        '/(?<![\w>$])app\s*\(/',
        '/(?<![\w>$])resolve\s*\(/',
        '/Illuminate\\\\Container/',
        '/Illuminate\\\\Support\\\\Facades/',
        '/\bContainer::/',
        // The service locator wearing a different hat: a static accessor that
        // hands back a globally configured collaborator is the same defect.
        '/\bApp::(make|get)\b/',
    ];

    $offenders = [];

    foreach (assuranceValueObjectFiles() as $file) {
        $source = (string) file_get_contents($file);

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $source) === 1) {
                $offenders[] = basename($file) . ' matches ' . $pattern;
            }
        }
    }

    expect($offenders)->toBe([]);
});

it('has no caller asking evidence to name its own level', function (): void {
    $offenders = [];

    foreach (shippedPhpFiles() as $file) {
        if (preg_match('/derivedAcr/', (string) file_get_contents($file)) === 1) {
            $offenders[] = basename($file);
        }
    }

    expect($offenders)->toBe([]);
});

it('never hard-codes the shipped vocabulary at a call site', function (): void {
    /*
     * The hole this closes: a writer can satisfy "does not touch the container"
     * by constructing NistAssuranceVocabulary itself. Nothing would fail — the
     * suite's default binding IS that class — while a host's custom vocabulary
     * is silently ignored everywhere it matters. Only the service provider,
     * which is where the host's choice is registered and overridden, may name
     * the concrete class.
     */
    $offenders = [];

    foreach (shippedPhpFiles() as $file) {
        if (basename($file) === 'VouchServiceProvider.php') {
            continue;
        }

        $source = (string) file_get_contents($file);

        if (preg_match('/new\s+\\\\?(Fissible\\\\Vouch\\\\Kernel\\\\Assurance\\\\)?NistAssuranceVocabulary/', $source) === 1) {
            $offenders[] = basename($file);
        }
    }

    expect($offenders)->toBe([]);
});

it('never resolves the vocabulary out of the container in shipped code', function (): void {
    /*
     * The defect one layer out. Deleting derivedAcr() and then writing
     * app(AssuranceVocabulary::class) in the middleware moves the ambient
     * lookup rather than removing it, and every behavioural test in this change
     * would still pass -- the container returns the host's binding either way.
     * What is lost is the property the issue is about: a service's
     * collaborators are visible in its signature.
     *
     * Only the provider, which is where the binding is registered, may name it
     * to the container.
     */
    $offenders = [];

    foreach (shippedPhpFiles() as $file) {
        if (basename($file) === 'VouchServiceProvider.php') {
            continue;
        }

        $source = (string) file_get_contents($file);

        $ambient = [
            // app(X::class), resolve(X::class)
            '/(app|resolve)\s*\([^)]*AssuranceVocabulary::class/',
            // app()->make(X::class), $container->make(X::class), Container::getInstance()->make(...)
            '/->\s*(make|makeWith|get)\s*\([^)]*AssuranceVocabulary::class/',
        ];

        if (array_filter($ambient, static fn (string $p): bool => preg_match($p, $source) === 1) !== []) {
            $offenders[] = basename($file);
        }
    }

    expect($offenders)->toBe([]);
});

it('injects the vocabulary into every service that names a level', function (): void {
    /*
     * All five settled call sites. An earlier draft covered only two, on the
     * grounds that SessionLifecycle and TokenAssuranceRecord could plausibly
     * receive a name from their caller instead. The contract now rules that
     * out: SessionLifecycle re-derives from the persisted factors rather than
     * reusing AuthSuccess::$acr, because that string names $success->facts
     * while the stored proof is built from $success->factors.
     *
     * Structural, and deliberately paired with the custom-vocabulary seam tests
     * in AcrWriterRoutingTest and AcrProjectionTest. Neither kind is sufficient
     * alone: this one cannot prove the injected instance is the one consulted,
     * and a behavioural test cannot prove a sixth caller has not appeared. It
     * is also satisfiable by an unused property, which is precisely why the
     * seam tests carry the contract.
     */
    $services = [
        'src/Assurance/EvidenceComparator.php',
        'src/Http/Middleware/RequireAbilityAssurance.php',
        'src/Sessions/SessionLifecycle.php',
        'src/Tokens/TokenAssuranceRecord.php',
        'src/SelfService/CredentialSelfService.php',
    ];

    $missing = [];

    foreach ($services as $relative) {
        $source = (string) file_get_contents(__DIR__ . '/../../' . $relative);

        if (preg_match('/AssuranceVocabulary\s+\$\w+/', $source) !== 1) {
            $missing[] = $relative;
        }
    }

    expect($missing)->toBe([]);
});
