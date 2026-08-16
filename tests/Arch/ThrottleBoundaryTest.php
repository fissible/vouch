<?php

declare(strict_types=1);

/** @return list<string> */
function throttleProductionFiles(): array
{
    $root = __DIR__ . '/../../src';
    $files = [];
    /** @var iterable<SplFileInfo> $found */
    $found = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

    foreach ($found as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $files[] = $file->getPathname();
        }
    }

    return $files;
}

it('keeps production factor challenge calls inside ChallengeIssuer', function (): void {
    $pattern = '~->\s*challenge\s*\(\s*new\s+[\\\\A-Za-z0-9_]*ChallengeRequest\s*\(~';
    $offenders = [];

    foreach (throttleProductionFiles() as $file) {
        if (basename($file) === 'ChallengeIssuer.php') {
            continue;
        }

        if (preg_match($pattern, (string) file_get_contents($file)) === 1) {
            $offenders[] = $file;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders))
        ->and(preg_match($pattern, '<?php $factor->challenge(new ChallengeRequest($attempt));'))
        ->toBe(1)
        ->and(preg_match(
            $pattern,
            '<?php $factor->challenge(new \\Fissible\\Vouch\\Factors\\ChallengeRequest($attempt));',
        ))->toBe(1);
});

it('keeps provider delivery calls inside the outbox worker', function (): void {
    $pattern = '/->\s*deliver\s*\(/';
    $offenders = [];

    foreach (throttleProductionFiles() as $file) {
        if (in_array(basename($file), ['OtpOutboxDelivery.php', 'DeliverOtpChallenge.php'], true)) {
            continue;
        }

        if (preg_match($pattern, (string) file_get_contents($file)) === 1) {
            $offenders[] = $file;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});

it('keeps the host proxy trust decision at the HTTP entry point', function (): void {
    $offenders = [];

    foreach (throttleProductionFiles() as $file) {
        if (basename($file) === 'AuthController.php') {
            continue;
        }

        if (preg_match('/\$request\s*->\s*ip\s*\(/', (string) file_get_contents($file)) === 1) {
            $offenders[] = $file;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});
