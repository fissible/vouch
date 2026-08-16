<?php

declare(strict_types=1);

use Pest\Mutate\MutationTest;

/*
 * The durable control for a confirmed pest-plugin-mutate defect.
 *
 * The plugin hands each child one --filter regex alternating every test that
 * covers the mutated lines. src/VouchServiceProvider.php is touched by 453 tests
 * -- every test that boots the package -- and the resulting pattern is large
 * enough that PCRE refuses to compile it. PHPUnit's NameFilterIterator calls
 * preg_match() with the diagnostic suppressed and compares === 1, so a
 * compilation failure is indistinguishable from "no test matched": the child
 * selects zero tests, prints "No tests found", and exits 0. MutationTest scores
 * exit 0 as a surviving mutant, so all 56 provider mutations were reported
 * UNTESTED while the tests that kill 42 of them were never run.
 *
 * patches/pest-plugin-mutate-3.0.5-chunk-filters.patch splits the filter into
 * compilable chunks and requires EVERY chunk to pass before a mutation counts as
 * survived. These assertions are the gate on that patch: they fail loudly if a
 * composer update drops it, which would otherwise silently restore 56 phantom
 * survivors.
 *
 * The fixture is the plugin's own derived filter set for that file, captured
 * from an instrumented run -- not a reconstruction.
 */

/**
 * @return array<int, string>
 */
function providerCoveringFilters(): array
{
    $path = __DIR__ . '/../Fixtures/provider-covering-filters.txt';
    $contents = file_get_contents($path);

    expect($contents)->not->toBeFalse();

    return array_values(array_filter(explode("\n", (string) $contents), static fn (string $l): bool => $l !== ''));
}

it('still declares the patch that keeps derived filters compilable', function (): void {
    /*
     * The behavioural assertions below prove the patch WORKS. This one proves
     * the project still asks for it, which is the half that a composer update
     * can quietly undo: drop the extra.patches entry and the next clean install
     * ships an unpatched plugin that silently reports phantom survivors again.
     *
     * The version is pinned exactly because a patch is written against one
     * version's source; a bumped plugin with a stale patch must fail the install
     * loudly rather than apply fuzzily.
     */
    $root = __DIR__ . '/../../';

    // Narrowed with real checks rather than casts: json_decode yields mixed, and
    // a malformed composer.json should say so plainly instead of failing later
    // as an unreadable type error.
    $decoded = json_decode((string) file_get_contents($root . 'composer.json'), true);

    if (! is_array($decoded)) {
        throw new RuntimeException('composer.json did not decode to an array.');
    }

    $config = $decoded['config'] ?? null;
    $requireDev = $decoded['require-dev'] ?? null;
    $extra = $decoded['extra'] ?? null;

    if (! is_array($config) || ! is_array($requireDev) || ! is_array($extra)) {
        throw new RuntimeException('composer.json is missing config, require-dev, or extra.');
    }

    $byPackage = $extra['patches'] ?? null;

    if (! is_array($byPackage)) {
        throw new RuntimeException('composer.json declares no extra.patches.');
    }

    $patches = $byPackage['pestphp/pest-plugin-mutate'] ?? null;

    if (! is_array($patches)) {
        throw new RuntimeException('No patches declared for pestphp/pest-plugin-mutate.');
    }

    expect($patches)->not->toBeEmpty()
        // A complete Phase 2 pass now takes about 51 minutes. Composer's
        // default 300-second child timeout killed the real gate while a direct
        // Pest invocation passed, so the CI-facing script needs its own bound.
        ->and($config['process-timeout'] ?? null)->toBeGreaterThanOrEqual(3_600)
        ->and($requireDev['pestphp/pest-plugin-mutate'] ?? null)->toBe('3.0.5')
        ->and($extra['composer-exit-on-patch-failure'] ?? null)->toBeTrue();

    foreach ($patches as $file) {
        if (! is_string($file)) {
            throw new RuntimeException('A declared patch path is not a string.');
        }

        expect(file_exists($root . $file))->toBeTrue("missing patch file: {$file}");
    }
});

it('reproduces the upstream defect: the unchunked provider filter will not compile', function (): void {
    /*
     * The self-contained reproduction, kept executable rather than only written
     * down, so the upstream report stays honest and we notice if a future PCRE
     * raises the ceiling and makes the patch unnecessary.
     */
    $filters = providerCoveringFilters();
    $pattern = '"' . implode('|', $filters) . '"';

    expect($filters)->toHaveCount(453)
        ->and(strlen($pattern))->toBeGreaterThan(34_000);

    // The exact failure the plugin walks into. The handler swap is only to keep
    // the expected warning out of the suite output -- PHPUnit's error handler
    // reports it through @ otherwise.
    set_error_handler(static fn (): bool => true);

    try {
        $matched = preg_match($pattern, 'AnyTest::anything');
    } finally {
        restore_error_handler();
    }

    expect($matched)->toBeFalse()
        ->and(preg_last_error())->toBe(PREG_INTERNAL_ERROR)
        ->and(preg_last_error_msg())->toBe('Internal error');
});

it('splits the 453-test provider set into chunks PCRE can compile', function (): void {
    $filters = providerCoveringFilters();

    $chunks = MutationTest::chunkFilters($filters);

    expect($chunks)->not->toBeEmpty()
        ->and(count($chunks))->toBeGreaterThan(1);

    foreach ($chunks as $index => $chunk) {
        expect($chunk)->not->toBeEmpty();

        // The property that actually matters: each child gets a filter that
        // compiles, so it can select tests instead of silently selecting none.
        expect(MutationTest::compiles($chunk))->toBeTrue("chunk {$index} does not compile");
        expect(@preg_match('"' . implode('|', $chunk) . '"', ''))->not->toBeFalse();
    }
});

it('loses no covering test when it chunks', function (): void {
    /*
     * Chunking must partition, not sample. A dropped test is a test that cannot
     * kill its mutant, which is the same silent failure in a smaller costume.
     */
    $filters = providerCoveringFilters();

    $flattened = array_merge(...MutationTest::chunkFilters($filters));

    expect($flattened)->toHaveCount(count($filters))
        ->and($flattened)->toBe($filters);
});

it('leaves a filter that already compiles as a single chunk', function (): void {
    // The common case must behave exactly as upstream does: one child, one
    // filter, no behavioural change for the other 89 covered files.
    $small = array_slice(providerCoveringFilters(), 0, 20);

    expect(MutationTest::chunkFilters($small))->toBe([$small]);
});

it('splits far enough even when the byte budget is set absurdly high', function (): void {
    /*
     * The limit is on the COMPILED pattern, not on source bytes, so no byte
     * budget is portable. The patch verifies each chunk by compiling it and
     * halves anything that still fails; this pins that fallback by handing it a
     * budget that guarantees the first pass produces an uncompilable chunk.
     */
    $chunks = MutationTest::chunkFilters(providerCoveringFilters(), maxBytes: PHP_INT_MAX);

    expect(count($chunks))->toBeGreaterThan(1);

    foreach ($chunks as $chunk) {
        expect(MutationTest::compiles($chunk))->toBeTrue();
    }
});
