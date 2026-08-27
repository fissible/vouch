<?php

declare(strict_types=1);

/*
 * Task 6's real commitment is architectural, not textual.
 *
 * "Suggest spatie, never require it" is a decision recorded in PROJECT.md: a
 * library that requires another library it does not itself call imposes an
 * architecture choice on every consumer and inherits its release cycle. A
 * suggest line in composer.json is the enforceable half of that; these tests
 * are what stop it drifting into a require during some later convenience.
 */

/**
 * @return array<string, mixed>
 */
function vouchComposerManifest(): array
{
    $raw = file_get_contents(dirname(__DIR__, 2) . '/composer.json');

    if ($raw === false) {
        throw new RuntimeException('composer.json is unreadable.');
    }

    $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

    if (! is_array($decoded)) {
        throw new RuntimeException('composer.json did not decode to an object.');
    }

    /** @var array<string, mixed> $decoded */
    return $decoded;
}

/**
 * @return array<string, string>
 */
function vouchComposerSection(string $section): array
{
    $value = vouchComposerManifest()[$section] ?? [];

    if (! is_array($value)) {
        throw new RuntimeException(sprintf('composer.json "%s" is not an object.', $section));
    }

    /** @var array<string, string> $value */
    return $value;
}

it('suggests spatie/laravel-permission', function (): void {
    expect(vouchComposerSection('suggest'))->toHaveKey('spatie/laravel-permission');
});

it('states the boundary in the suggestion, not just the word authentication', function (): void {
    /*
     * The suggestion is read in isolation, on Packagist, by someone deciding
     * what this package is. It has to say BOTH halves — that Vouch does
     * authentication, and that what the other package does is the part Vouch
     * leaves alone. One half without the other is not a boundary.
     */
    $suggestion = vouchComposerSection('suggest')['spatie/laravel-permission'] ?? '';

    expect($suggestion)->toMatch('/authentication/i')
        ->and($suggestion)->toMatch('/authorization|permission|role/i');
});

it('does not require an authorization package at runtime', function (string $package): void {
    /*
     * The load-bearing assertion in this file. Authorization is out of scope,
     * and the moment one of these appears in require, every consumer inherits
     * a role model, a migration set and a release cycle they did not choose.
     */
    expect(array_keys(vouchComposerSection('require')))->not->toContain($package);
})->with(['spatie/laravel-permission', 'silber/bouncer']);

it('keeps both authorization packages as dev dependencies', function (string $package): void {
    /*
     * Not Task 6's packaging contract — a fixture guard for Task 5a, kept
     * because those probes are permanent committed tests rather than a
     * one-off measurement. Dropping either package would not fail a test; it
     * would silently stop measuring, and the survey would rot back into the
     * assumptions it was written to replace.
     */
    expect(array_keys(vouchComposerSection('require-dev')))->toContain($package);
})->with(['spatie/laravel-permission', 'silber/bouncer']);

it('never imports or class-references an authorization package in src', function (): void {
    /*
     * RouteAbilityScanner names Spatie's middleware classes, but as STRING
     * constants, deliberately: a real reference would turn an optional
     * package into a hard one and fatal on a host that never installed it.
     * This keeps that deliberate awkwardness from being "tidied up" into an
     * import.
     *
     * Grouped imports and ::class references count too, because each is a
     * compile-time reference. A quoted class NAME is not, which is exactly
     * the distinction the scanner relies on.
     */
    $offenders = [];
    $vendors = 'Spatie\\\\Permission|Silber\\\\Bouncer';
    $import = '/^use\\s+\\\\?(' . $vendors . ')[\\\\{]/m';
    $reference = '/(?<![\'"\\\\])\\\\?(' . $vendors . ')\\\\[A-Za-z0-9_\\\\]*::/';

    /** @var SplFileInfo $file */
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__, 2) . '/src')) as $file) {
        if ($file->getExtension() !== 'php') {
            continue;
        }

        $contents = (string) file_get_contents($file->getPathname());

        if (preg_match($import, $contents) === 1 || preg_match($reference, $contents) === 1) {
            $offenders[] = $file->getPathname();
        }
    }

    expect($offenders)->toBe([]);
});
