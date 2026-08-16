<?php

declare(strict_types=1);

use Fissible\Vouch\Sessions\BindingDomain;

function referencesThrottleDerivation(string $source): bool
{
    $tokens = array_values(array_filter(
        token_get_all($source),
        static fn (array|string $token): bool => ! is_array($token)
            || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
    ));

    foreach ($tokens as $index => $token) {
        $name = is_array($token) ? $token[1] : $token;
        $separator = $tokens[$index + 1] ?? null;
        $member = $tokens[$index + 2] ?? null;
        $separatorName = is_array($separator) ? $separator[1] : $separator;
        $memberName = is_array($member) ? $member[1] : $member;
        $isSessionBinding = $name === 'SessionBinding'
            || str_ends_with($name, '\\SessionBinding');
        $isBindingDomain = $name === 'BindingDomain'
            || str_ends_with($name, '\\BindingDomain');

        if (
            $separatorName === '::'
            && (
                ($isSessionBinding && $memberName === 'forSegments')
                || ($isBindingDomain && str_starts_with((string) $memberName, 'Throttle'))
            )
        ) {
            return true;
        }
    }

    return false;
}

function constructsThrottleSubject(string $source): bool
{
    $tokens = array_values(array_filter(
        token_get_all($source),
        static fn (array|string $token): bool => ! is_array($token)
            || ! in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
    ));

    foreach ($tokens as $index => $token) {
        if (! is_array($token) || $token[0] !== T_NEW) {
            continue;
        }

        $class = $tokens[$index + 1] ?? null;
        $name = is_array($class) ? $class[1] : $class;

        if ($name === 'ThrottleSubject' || str_ends_with((string) $name, '\\ThrottleSubject')) {
            return true;
        }
    }

    return false;
}

it('declares every throttle HMAC domain explicitly', function (): void {
    expect(array_map(
        static fn (BindingDomain $domain): array => [$domain->name, $domain->value],
        BindingDomain::cases(),
    ))->toBe([
        ['Session', 'session'],
        ['Attempt', 'attempt'],
        ['ThrottleIdentifier', 'throttle.identifier'],
        ['ThrottleRecovery', 'throttle.recovery'],
        ['ThrottleIssuance', 'throttle.issuance'],
        ['ThrottleIpV4', 'throttle.ipv4'],
        ['ThrottleIpV6', 'throttle.ipv6-prefix-64'],
        ['ThrottleIpIdentifier', 'throttle.ip-identifier'],
        ['ThrottleTenant', 'throttle.tenant'],
        ['ThrottleGlobal', 'throttle.global'],
    ]);
});

it('keeps HMAC and APP_KEY access inside SessionBinding', function (): void {
    $root = (string) realpath(__DIR__ . '/../../src');
    $offenders = [];

    /** @var iterable<SplFileInfo> $files */
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace($root . '/', '', $file->getPathname());

        if ($relative === 'Sessions/SessionBinding.php') {
            continue;
        }

        $source = (string) file_get_contents($file->getPathname());

        if (preg_match('/\bhash_hmac\s*\(|config\s*\(\s*[\'\"]app\.key[\'\"]/', $source) === 1) {
            $offenders[] = $relative;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});

it('keeps segmented throttle derivation behind ThrottleKey', function (): void {
    $root = (string) realpath(__DIR__ . '/../../src');
    $offenders = [];

    /** @var iterable<SplFileInfo> $files */
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace($root . '/', '', $file->getPathname());

        if (in_array($relative, ['Sessions/SessionBinding.php', 'Throttle/ThrottleKey.php'], true)) {
            continue;
        }

        if (referencesThrottleDerivation((string) file_get_contents($file->getPathname()))) {
            $offenders[] = $relative;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});

it('keeps production throttle-subject construction behind ThrottleKey', function (): void {
    $root = (string) realpath(__DIR__ . '/../../src');
    $offenders = [];

    /** @var iterable<SplFileInfo> $files */
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root));

    foreach ($files as $file) {
        if (! $file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $relative = str_replace($root . '/', '', $file->getPathname());

        if (in_array($relative, [
            'Throttle/ThrottleKey.php',
            'Throttle/ThrottleSubject.php',
        ], true)) {
            continue;
        }

        if (constructsThrottleSubject((string) file_get_contents($file->getPathname()))) {
            $offenders[] = $relative;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});

it('recognizes imported and fully qualified throttle-subject construction without matching prose', function (): void {
    expect(constructsThrottleSubject('<?php new ThrottleSubject($dimension, $digest);'))
        ->toBeTrue()
        ->and(constructsThrottleSubject(
            '<?php new \\Fissible\\Vouch\\Throttle\\ThrottleSubject($dimension, $digest);',
        ))->toBeTrue()
        ->and(constructsThrottleSubject(
            '<?php // new ThrottleSubject($dimension, $digest);',
        ))->toBeFalse()
        ->and(constructsThrottleSubject(
            '<?php $message = "new ThrottleSubject($dimension, $digest)";',
        ))->toBeFalse();
});

it('recognizes imported and fully qualified derivation calls without matching prose', function (): void {
    expect(referencesThrottleDerivation('<?php SessionBinding::forSegments($domain, $id);'))
        ->toBeTrue()
        ->and(referencesThrottleDerivation(
            '<?php \\Fissible\\Vouch\\Sessions\\BindingDomain::ThrottleIdentifier;',
        ))->toBeTrue()
        ->and(referencesThrottleDerivation(
            '<?php // SessionBinding::forSegments($domain, $id);',
        ))->toBeFalse()
        ->and(referencesThrottleDerivation(
            '<?php $message = "BindingDomain::ThrottleIdentifier";',
        ))->toBeFalse();
});

it('forbids local subject concatenation in ThrottleKey', function (): void {
    $files = [__DIR__ . '/../../src/Throttle/ThrottleKey.php'];

    expect(is_file($files[0]))->toBeTrue();

    $offenders = [];

    foreach ($files as $file) {
        $tokens = token_get_all((string) file_get_contents($file));

        foreach ($tokens as $token) {
            if ($token === '.') {
                $offenders[] = basename($file);
                break;
            }
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});
