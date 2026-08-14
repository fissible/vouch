<?php

declare(strict_types=1);

/*
 * tests/TestCase.php lowers hashing.bcrypt.rounds to 4 so the mutation gate is
 * affordable. That is a safe thing to do in a test run and an unsafe thing to
 * ship: a host application that somehow inherited it would hash every password
 * in production at the weakest cost bcrypt accepts, silently, with no failing
 * test anywhere to say so.
 *
 * "It lives under tests/, so it cannot load" is an assumption about packaging,
 * not a control. These are the controls. Each one independently prevents the
 * override from reaching a host, so the barrier survives any single one of them
 * being wrong.
 */

/** @return array<string, mixed> */
function composerManifest(): array
{
    $raw = file_get_contents(__DIR__ . '/../../composer.json');

    if ($raw === false) {
        throw new RuntimeException('composer.json is unreadable.');
    }

    $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

    if (! is_array($decoded)) {
        throw new RuntimeException('composer.json did not decode to an array.');
    }

    /** @var array<string, mixed> */
    return $decoded;
}

it('never sets a hashing cost from shipped code', function (): void {
    /*
     * The first and most direct control. Nothing under src/ or config/ may touch
     * the host's hashing configuration at all -- not the rounds, not the driver.
     * Choosing a password hashing cost is the host application's decision, and a
     * package that quietly overrides it is a defect regardless of which
     * direction it moves the number.
     */
    $offenders = [];

    foreach (['src', 'config'] as $directory) {
        $files = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(__DIR__ . '/../../' . $directory, FilesystemIterator::SKIP_DOTS),
        );

        foreach ($files as $file) {
            assert($file instanceof SplFileInfo);

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $contents = (string) file_get_contents($file->getPathname());

            // Prose mentioning hashing is fine; a config write is not.
            if (preg_match('/[\'"]hashing[.\'"]/', $contents) === 1) {
                $offenders[] = $file->getPathname();
            }
        }
    }

    // Names the files rather than asserting a bare count, so a failure says
    // which file to look at.
    expect($offenders)->toBe([]);
});

it('scans a non-empty set of shipped files', function (): void {
    // Guards the test above: a mistyped path would scan nothing and pass.
    $count = 0;

    $files = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator(__DIR__ . '/../../src', FilesystemIterator::SKIP_DOTS),
    );

    foreach ($files as $file) {
        assert($file instanceof SplFileInfo);

        if ($file->getExtension() === 'php') {
            $count++;
        }
    }

    expect($count)->toBeGreaterThan(50);
});

it('keeps the test namespace out of the production autoloader', function (): void {
    /*
     * A host installing vouch gets `autoload`, never `autoload-dev`. If
     * Fissible\Vouch\Tests\ ever appeared in the former, TestCase would become a
     * loadable class in a production application.
     */
    $manifest = composerManifest();

    $autoload = $manifest['autoload'] ?? [];
    assert(is_array($autoload));
    $psr4 = $autoload['psr-4'] ?? [];
    assert(is_array($psr4));

    expect(array_keys($psr4))->toBe(['Fissible\\Vouch\\'])
        ->and($psr4['Fissible\\Vouch\\'])->toBe('src/');
});

it('keeps the test harness in require-dev so TestCase cannot even be constructed', function (): void {
    /*
     * The last line of defence, and the reason the other two can be trusted.
     * TestCase extends Orchestra\Testbench\TestCase. Testbench is a dev
     * dependency, so in a production install the parent class does not exist and
     * the file cannot be loaded even if something reached for it directly.
     */
    $manifest = composerManifest();

    $require = $manifest['require'] ?? [];
    $requireDev = $manifest['require-dev'] ?? [];
    assert(is_array($require) && is_array($requireDev));

    expect($requireDev)->toHaveKey('orchestra/testbench')
        ->and($require)->not->toHaveKey('orchestra/testbench')
        ->and($require)->not->toHaveKey('pestphp/pest');
});

it('excludes the test suite from the distributed package', function (): void {
    /*
     * Belt to the braces above: export-ignore keeps tests/ out of the dist
     * archive entirely, so the file a host receives does not contain the
     * override at all.
     */
    $attributes = file_get_contents(__DIR__ . '/../../.gitattributes');

    expect($attributes)->toBeString()
        ->and($attributes)->toContain('/tests')
        ->and($attributes)->toContain('export-ignore');
});
