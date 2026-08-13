<?php

declare(strict_types=1);

/*
 * ErrorShaper discloses Outcome::Locked in FULL under every posture, including
 * strict — message and RetryPolicy both survive. Its own docblock states the
 * precondition: that is safe only if rate limits apply identically to known and
 * unknown identifiers, including the length of the window.
 *
 * Phase 2.3 ships no rate limiting. So a known identifier would return a
 * populated retry state while an unknown one returned the uniform message with
 * retry: null — a complete account-existence oracle obtained UNDER STRICT
 * POSTURE, with every kernel test green.
 *
 * Until 2.3b can satisfy the precondition, no 2.3 path may reach that carve-out.
 * ScreenBuilder guards its own entry point; this makes the ban structural.
 */

/** @return list<string> */
function lockoutScannedFiles(): array
{
    $roots = ['src/Flow', 'src/Http', 'src/Sessions', 'src/Recovery'];
    $files = [];

    foreach ($roots as $root) {
        $path = __DIR__ . '/../../' . $root;

        if (! is_dir($path)) {
            continue;
        }

        /** @var iterable<SplFileInfo> $found */
        $found = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));

        foreach ($found as $file) {
            if ($file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file->getPathname();
            }
        }
    }

    return $files;
}

it('scans a non-empty set of 2.3-owned files', function (): void {
    // Without this, a mistyped root would make the ban below vacuously green.
    expect(lockoutScannedFiles())->not->toBeEmpty();
});

it('never reaches a lockout path from 2.3-owned source', function (): void {
    /*
     * Each pattern tolerates a namespace prefix. The first draft of the
     * RetryPolicy pattern matched only `new RetryPolicy(` and `new
     * \RetryPolicy(` — a fully-qualified `new \Fissible\Vouch\Kernel\Screen\
     * RetryPolicy(` slipped straight through, which is the form someone would
     * actually write. The probe caught it; the pattern now allows any leading
     * namespace path.
     */
    $namespaced = '(?:\\\\?[A-Za-z_][A-Za-z0-9_]*\\\\)*';

    $banned = [
        'Outcome::Locked' => '/\b' . $namespaced . 'Outcome\s*::\s*Locked\b/',
        'AttemptState::Locked' => '/\b' . $namespaced . 'AttemptState\s*::\s*Locked\b/',
        'new RetryPolicy' => '/\bnew\s+' . $namespaced . 'RetryPolicy\s*\(/',
    ];

    $offenders = [];

    foreach (lockoutScannedFiles() as $file) {
        $source = (string) file_get_contents($file);

        foreach ($banned as $label => $pattern) {
            /*
             * ScreenBuilder names Outcome::Locked in order to REFUSE it. That is
             * the one legitimate mention, and it is a comparison rather than a
             * construction — so it is excluded by name rather than by loosening
             * the pattern for every file.
             */
            if ($label === 'Outcome::Locked' && str_ends_with($file, 'ScreenBuilder.php')) {
                continue;
            }

            if (preg_match($pattern, $source) === 1) {
                $offenders[] = basename($file) . ' :: ' . $label;
            }
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});
