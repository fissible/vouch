<?php

declare(strict_types=1);

use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\SharedThrottle;

/** @return list<string> */
function lockoutProductionFiles(): array
{
    $root = realpath(__DIR__ . '/../../src');

    if (! is_string($root)) {
        throw new RuntimeException('The production source root does not exist.');
    }

    $files = [];
    /** @var iterable<SplFileInfo> $found */
    $found = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
    );

    foreach ($found as $file) {
        if ($file->isFile() && $file->getExtension() === 'php') {
            $files[] = $file->getPathname();
        }
    }

    sort($files);

    return $files;
}

/** @return list<array{0: int, 1: string, 2: int}|string> */
function lockoutTokens(string $source): array
{
    $tokens = [];

    foreach (token_get_all($source) as $token) {
        if (is_array($token)
            && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
            continue;
        }

        $tokens[] = $token;
    }

    return $tokens;
}

/** @param array{0: int, 1: string, 2: int}|string $token */
function lockoutTokenText(array|string $token): string
{
    return is_array($token) ? $token[1] : $token;
}

function lockoutConstructionCount(string $source, string $shortClass): int
{
    $tokens = lockoutTokens($source);
    $count = 0;

    foreach ($tokens as $index => $token) {
        if (! is_array($token) || $token[0] !== T_NEW) {
            continue;
        }

        $name = lockoutTokenText($tokens[$index + 1] ?? '');

        if ($name === $shortClass || str_ends_with($name, '\\' . $shortClass)) {
            $count++;
        }
    }

    return $count;
}

function lockoutMethodCallCount(string $source, string $method): int
{
    $tokens = lockoutTokens($source);
    $count = 0;

    foreach ($tokens as $index => $token) {
        $operator = lockoutTokenText($token);

        if (! in_array($operator, ['->', '?->', '::'], true)) {
            continue;
        }

        if (lockoutTokenText($tokens[$index + 1] ?? '') === $method
            && lockoutTokenText($tokens[$index + 2] ?? '') === '(') {
            $count++;
        }
    }

    return $count;
}

function lockoutMethodSource(ReflectionMethod $method): string
{
    $file = $method->getFileName();
    $start = $method->getStartLine();
    $end = $method->getEndLine();

    if (! is_string($file) || ! is_int($start) || ! is_int($end)) {
        throw new RuntimeException('Cannot locate the lock-writer method.');
    }

    $lines = file($file);

    if (! is_array($lines)) {
        throw new RuntimeException('Cannot read the lock-writer source.');
    }

    return implode('', array_slice($lines, $start - 1, ($end - $start) + 1));
}

it('scans a non-empty set of production files', function (): void {
    expect(lockoutProductionFiles())->not->toBeEmpty();
});

it('keeps every RetryPolicy construction at the disclosure boundary', function (): void {
    $root = realpath(__DIR__ . '/../../src');

    if (! is_string($root)) {
        throw new RuntimeException('The production source root does not exist.');
    }

    $owners = [];

    foreach (lockoutProductionFiles() as $file) {
        $count = lockoutConstructionCount((string) file_get_contents($file), 'RetryPolicy');

        if ($count > 0) {
            $owners[str_replace($root . '/', '', $file)] = $count;
        }
    }

    expect($owners)->toBe([
        'Flow/ScreenBuilder.php' => 2,
        'Kernel/Enumeration/ErrorShaper.php' => 2,
    ]);
});

it('has exactly one private identifier-lock write call site', function (): void {
    $writer = new ReflectionMethod(DatabaseAuthThrottleStore::class, 'writeLock');
    $writerSource = lockoutMethodSource($writer);
    $recordSource = lockoutMethodSource(new ReflectionMethod(
        DatabaseAuthThrottleStore::class,
        'recordIdentifierFailure',
    ));
    $storeSource = (string) file_get_contents(
        __DIR__ . '/../../src/Throttle/DatabaseAuthThrottleStore.php',
    );

    expect($writer->isPrivate())->toBeTrue()
        ->and(substr_count($storeSource, '$this->writeLock('))->toBe(1)
        ->and($recordSource)->toContain('$this->writeLock(')
        ->and($writerSource)->toContain("'auth_throttle_locks'")
        ->and($writerSource)->toContain("'locked_until'")
        ->and($writerSource)->toContain('deadlineSqlHere()');
});

it('keeps every lock-table mutation in the identifier store except pruning deletes', function (): void {
    $root = realpath(__DIR__ . '/../../src');

    if (! is_string($root)) {
        throw new RuntimeException('The production source root does not exist.');
    }

    $owners = [];

    foreach (lockoutProductionFiles() as $file) {
        $source = (string) file_get_contents($file);
        $relative = str_replace($root . '/', '', $file);

        /*
         * RetentionManifest DECLARES which tables have a reclaimer. It names
         * this one without touching it, and a declaration is not a mutation.
         * Excluded by name rather than by loosening the scan, so a genuine new
         * writer still lands in $owners and fails.
         */
        if ($relative === 'Console/RetentionManifest.php') {
            continue;
        }

        if (str_contains($source, "'auth_throttle_locks'")) {
            $owners[] = $relative;
        }
    }

    expect($owners)->toBe([
        'Console/VouchPruneCommand.php',
        'Throttle/DatabaseAuthThrottleStore.php',
    ]);

    $prune = (string) file_get_contents(__DIR__ . '/../../src/Console/VouchPruneCommand.php');

    expect(lockoutMethodCallCount($prune, 'insert'))->toBe(0)
        ->and(lockoutMethodCallCount($prune, 'insertOrIgnore'))->toBe(0)
        ->and(lockoutMethodCallCount($prune, 'update'))->toBe(0);
});

it('makes populated lock state unrepresentable for shared dimensions', function (): void {
    $properties = array_map(
        static fn (ReflectionProperty $property): string => $property->getName(),
        (new ReflectionClass(SharedThrottle::class))->getProperties(ReflectionProperty::IS_PUBLIC),
    );
    $sharedSource = (string) file_get_contents(__DIR__ . '/../../src/Throttle/SharedThrottle.php');
    $sharedTokens = array_map(
        static fn (array|string $token): string => lockoutTokenText($token),
        lockoutTokens($sharedSource),
    );
    $retrySource = lockoutMethodSource(new ReflectionMethod(
        \Fissible\Vouch\Flow\ScreenBuilder::class,
        'retryPolicy',
    ));

    expect($properties)->toBe(['decision', 'retryAfter'])
        ->and($sharedTokens)->not->toContain('lockedUntil')
        ->and($retrySource)->toContain('if ($throttle instanceof SharedThrottle)')
        ->and($retrySource)->toContain('lockedUntil: null');
});

it('recognizes imported and fully qualified retry construction without matching prose', function (): void {
    expect(lockoutConstructionCount('<?php new RetryPolicy(null, null);', 'RetryPolicy'))
        ->toBe(1)
        ->and(lockoutConstructionCount(
            '<?php new \\Fissible\\Vouch\\Kernel\\Screen\\RetryPolicy(null, null);',
            'RetryPolicy',
        ))->toBe(1)
        ->and(lockoutConstructionCount(
            '<?php // new RetryPolicy(null, null);',
            'RetryPolicy',
        ))->toBe(0)
        ->and(lockoutConstructionCount(
            '<?php $message = "new RetryPolicy(null, null)";',
            'RetryPolicy',
        ))->toBe(0);
});
