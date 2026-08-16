<?php

declare(strict_types=1);

/** @return list<string> */
function throttleProductionFiles(): array
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
function throttleBoundaryTokens(string $source): array
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
function throttleBoundaryTokenText(array|string $token): string
{
    return is_array($token) ? $token[1] : $token;
}

function throttleBoundaryMethodCallCount(string $source, string $method): int
{
    $tokens = throttleBoundaryTokens($source);
    $count = 0;

    foreach ($tokens as $index => $token) {
        if (! in_array(throttleBoundaryTokenText($token), ['->', '?->', '::'], true)) {
            continue;
        }

        if (throttleBoundaryTokenText($tokens[$index + 1] ?? '') === $method
            && throttleBoundaryTokenText($tokens[$index + 2] ?? '') === '(') {
            $count++;
        }
    }

    return $count;
}

/** @return list<string> */
function throttleBoundaryForwardingHeaders(string $source): array
{
    $headers = [];
    $forbidden = [
        'forwarded',
        'http_forwarded',
        'http_x_forwarded_for',
        'http_x_real_ip',
        'x-forwarded-for',
        'x-real-ip',
    ];

    foreach (throttleBoundaryTokens($source) as $token) {
        if (! is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
            continue;
        }

        $literal = strtolower(substr($token[1], 1, -1));

        if (in_array($literal, $forbidden, true)) {
            $headers[] = $literal;
        }
    }

    return $headers;
}

/** @return list<string> */
function throttleBoundaryRawColumns(string $source): array
{
    $tokens = throttleBoundaryTokens($source);
    $columns = [];
    $schemaMethods = ['char', 'ipAddress', 'string', 'text', 'uuid'];
    $forbidden = [
        'client_ip',
        'email',
        'identifier',
        'identifier_id',
        'ip',
        'ip_address',
        'phone',
        'subject',
        'tenant',
        'tenant_id',
        'user_id',
        'value',
    ];

    foreach ($tokens as $index => $token) {
        if (throttleBoundaryTokenText($token) !== '->') {
            continue;
        }

        $method = throttleBoundaryTokenText($tokens[$index + 1] ?? '');

        if (! in_array($method, $schemaMethods, true)
            || throttleBoundaryTokenText($tokens[$index + 2] ?? '') !== '(') {
            continue;
        }

        $argument = $tokens[$index + 3] ?? null;

        if (! is_array($argument) || $argument[0] !== T_CONSTANT_ENCAPSED_STRING) {
            continue;
        }

        $column = substr($argument[1], 1, -1);

        if (in_array($column, $forbidden, true)) {
            $columns[] = $column;
        }
    }

    return $columns;
}

function throttleBoundaryLoggingCallCount(string $source): int
{
    $tokens = throttleBoundaryTokens($source);
    $count = 0;

    foreach ($tokens as $index => $token) {
        $name = throttleBoundaryTokenText($token);

        if ($name === 'logger'
            && throttleBoundaryTokenText($tokens[$index + 1] ?? '') === '(') {
            $count++;
        }

        if (($name === 'Log' || str_ends_with($name, '\\Log'))
            && throttleBoundaryTokenText($tokens[$index + 1] ?? '') === '::') {
            $count++;
        }
    }

    return $count;
}

it('scans a non-empty set of production files', function (): void {
    expect(throttleProductionFiles())->not->toBeEmpty();
});

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
    $offenders = [];

    foreach (throttleProductionFiles() as $file) {
        if (in_array(basename($file), ['OtpOutboxDelivery.php', 'DeliverOtpChallenge.php'], true)) {
            continue;
        }

        if (throttleBoundaryMethodCallCount((string) file_get_contents($file), 'deliver') > 0) {
            $offenders[] = $file;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});

it('keeps the host proxy trust decision at the one HTTP entry point', function (): void {
    $root = realpath(__DIR__ . '/../../src');

    if (! is_string($root)) {
        throw new RuntimeException('The production source root does not exist.');
    }

    $owners = [];
    $forwardingHeaders = [];

    foreach (throttleProductionFiles() as $file) {
        $source = (string) file_get_contents($file);
        $ipCalls = throttleBoundaryMethodCallCount($source, 'ip');

        if ($ipCalls > 0) {
            $owners[str_replace($root . '/', '', $file)] = $ipCalls;
        }

        foreach (throttleBoundaryForwardingHeaders($source) as $header) {
            $forwardingHeaders[] = $file . ' :: ' . $header;
        }
    }

    $clientIp = new ReflectionParameter(
        [\Fissible\Vouch\Flow\FlowRequest::class, '__construct'],
        'clientIp',
    );
    $type = $clientIp->getType();
    $authFlow = (string) file_get_contents($root . '/Flow/AuthFlow.php');
    $controller = (string) file_get_contents($root . '/Http/AuthController.php');
    $reporter = (string) file_get_contents($root . '/Throttle/ThrottleReporter.php');

    expect($owners)->toBe([
        'Flow/AuthFlow.php' => 2,
        'Http/AuthController.php' => 1,
        'Throttle/ThrottleReporter.php' => 2,
    ])
        ->and(substr_count($authFlow, '$this->throttleKey->ip('))->toBe(2)
        ->and(substr_count($controller, '$request->ip('))->toBe(1)
        ->and(substr_count($reporter, '$this->ip('))->toBe(2)
        ->and($controller)->toContain('clientIp: $request->ip()')
        ->and($forwardingHeaders)->toBeEmpty(implode("\n", $forwardingHeaders))
        ->and($type)->toBeInstanceOf(ReflectionNamedType::class)
        ->and($type instanceof ReflectionNamedType ? $type->getName() : null)->toBe('string')
        ->and($type?->allowsNull())->toBeTrue();
});

it('stores no raw throttle subject column', function (): void {
    $migrations = glob(__DIR__ . '/../../database/migrations/*auth_throttle*_table.php');

    if (! is_array($migrations)) {
        throw new RuntimeException('Cannot enumerate throttle migrations.');
    }

    sort($migrations);
    $offenders = [];

    foreach ($migrations as $migration) {
        foreach (throttleBoundaryRawColumns((string) file_get_contents($migration)) as $column) {
            $offenders[] = basename($migration) . ' :: ' . $column;
        }
    }

    expect($migrations)->toHaveCount(4)
        ->and($offenders)->toBeEmpty(implode("\n", $offenders));
});

it('keeps throttle and aggregate-report paths free of direct logging', function (): void {
    $offenders = [];

    foreach (throttleProductionFiles() as $file) {
        $relative = str_replace(
            (string) realpath(__DIR__ . '/../../src') . '/',
            '',
            $file,
        );

        if (! str_starts_with($relative, 'Throttle/')
            && ! in_array($relative, [
                'Console/VouchPruneCommand.php',
                'Console/VouchThrottleReportCommand.php',
            ], true)) {
            continue;
        }

        if (throttleBoundaryLoggingCallCount((string) file_get_contents($file)) > 0) {
            $offenders[] = $relative;
        }
    }

    expect($offenders)->toBeEmpty(implode("\n", $offenders));
});

it('recognizes imported and fully qualified IP reads without matching prose', function (): void {
    expect(throttleBoundaryMethodCallCount('<?php $request->ip();', 'ip'))->toBe(1)
        ->and(throttleBoundaryMethodCallCount('<?php $request?->ip();', 'ip'))->toBe(1)
        ->and(throttleBoundaryMethodCallCount('<?php Request::ip();', 'ip'))->toBe(1)
        ->and(throttleBoundaryMethodCallCount(
            '<?php \\Illuminate\\Http\\Request::ip();',
            'ip',
        ))->toBe(1)
        ->and(throttleBoundaryMethodCallCount('<?php // $request->ip();', 'ip'))->toBe(0)
        ->and(throttleBoundaryMethodCallCount('<?php $text = "$request->ip()";', 'ip'))->toBe(0);
});

it('recognizes raw schema, forwarding-header, and logging violations', function (): void {
    expect(throttleBoundaryRawColumns('<?php $table->string("identifier");'))
        ->toBe(['identifier'])
        ->and(throttleBoundaryRawColumns('<?php $table->char("subject_digest", 64);'))
        ->toBe([])
        ->and(throttleBoundaryForwardingHeaders('<?php $request->header("X-Forwarded-For");'))
        ->toBe(['x-forwarded-for'])
        ->and(throttleBoundaryForwardingHeaders('<?php // "X-Forwarded-For"'))
        ->toBe([])
        ->and(throttleBoundaryLoggingCallCount('<?php Log::info($identifier);'))->toBe(1)
        ->and(throttleBoundaryLoggingCallCount(
            '<?php \\Illuminate\\Support\\Facades\\Log::info($identifier);',
        ))->toBe(1)
        ->and(throttleBoundaryLoggingCallCount('<?php $message = "Log::info";'))->toBe(0);
});

it('documents every host-owned throttle boundary and deferred control', function (): void {
    $operations = (string) file_get_contents(__DIR__ . '/../../docs/operations.md');

    expect($operations)->toContain('Rotating that key deliberately')
        ->and($operations)->toContain('TrustProxies')
        ->and($operations)->toContain('IP, tenant, and global dimensions ship in observe mode')
        ->and($operations)->toContain('Tenant and global enforcement')
        ->and($operations)->toContain('remain opt-in')
        ->and($operations)->toContain('no administrative unlock')
        ->and($operations)->toContain('aggregate distributions')
        ->and($operations)->toContain('do not add candidate lookup or plaintext subject columns');
});
