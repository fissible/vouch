<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use FilesystemIterator;
use Fissible\Vouch\Http\Middleware\RejectsUnrecordedTokens;
use Illuminate\Console\Command;
use Illuminate\Routing\Router;
use JsonException;
use SplFileInfo;

/**
 * Surveys source issuance seams and the already-resolved router.  This is not
 * an authorization proof: where PHP's lexer cannot establish a call, that
 * uncertainty is itself a finding instead of a quiet omission.
 */
final class VouchAuditTokensCommand extends Command
{
    protected $signature = 'vouch:audit-tokens {--json : Emit machine-readable JSON} {--strict : Fail on source findings that require action}';
    protected $description = 'Report direct token issuance, unresolved issuance seams, and token-gate coverage.';

    /** @throws JsonException */
    public function handle(Router $router): int
    {
        $report = $this->report($router);

        if ($this->option('json') === true) {
            $this->line(json_encode($report, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
        } else {
            $this->render($report);
        }

        if ($this->option('strict') === true && $this->hasStrictFinding($report)) {
            return CommandExit::Failure->value;
        }

        return CommandExit::Success->value;
    }

    /**
     * @return array{issuance_sites: list<array{identifier: string, file: string, status: string, reviewed?: string}>, unknown_seams: list<array{identifier: string, file: string, reason: string}>, uncovered_routes: list<array{uri: string}>, allowlist_problems: list<array{identifier: string}>, scanned_paths: list<string>}
     */
    private function report(Router $router): array
    {
        $sites = [];
        $unknown = [];
        $scanned = [];

        $paths = config('vouch.audit.paths');
        if (! is_array($paths)) {
            $unknown[] = $this->pathSeam('vouch.audit.paths', 'configured audit paths are not a list');
        } else {
            foreach ($paths as $path) {
                if (! is_string($path) || $path === '') {
                    $unknown[] = $this->pathSeam(is_string($path) ? $path : 'vouch.audit.paths', 'configured audit path is not a non-empty string');

                    continue;
                }

                $this->scanPath($path, $sites, $unknown, $scanned);
            }
        }

        $allowlist = config('vouch.audit.allowlist');
        $allowlist = is_array($allowlist) ? $allowlist : [];
        $problems = [];
        $valid = [];
        foreach ($allowlist as $identifier => $entry) {
            if (! is_string($identifier)) {
                continue;
            }
            if (! is_array($entry) || ! $this->hasRequiredAllowlistFields($entry)) {
                $problems[$identifier] = true;

                continue;
            }
            $valid[$identifier] = $entry;
        }

        $seen = [];
        foreach ($sites as &$site) {
            $seen[$site['identifier']] = true;
            $entry = $valid[$site['identifier']] ?? null;
            if ($entry === null) {
                $site['status'] = 'reported';

                continue;
            }

            $site['status'] = 'allowlisted';
            $reviewed = $entry['reviewed'] ?? null;
            if (is_string($reviewed)) {
                $site['reviewed'] = $reviewed;
            }
        }
        unset($site);

        foreach (array_keys($valid) as $identifier) {
            if (! isset($seen[$identifier])) {
                $problems[$identifier] = true;
            }
        }

        $allowlistProblems = array_map(
            static fn (string $identifier): array => ['identifier' => $identifier],
            array_keys($problems),
        );
        usort($sites, static fn (array $left, array $right): int => [$left['identifier'], $left['file']] <=> [$right['identifier'], $right['file']]);
        usort($unknown, static fn (array $left, array $right): int => [$left['identifier'], $left['file']] <=> [$right['identifier'], $right['file']]);
        usort($allowlistProblems, static fn (array $left, array $right): int => $left['identifier'] <=> $right['identifier']);
        sort($scanned);

        return [
            'issuance_sites' => $sites,
            'unknown_seams' => $unknown,
            'uncovered_routes' => $this->uncoveredRoutes($router),
            'allowlist_problems' => $allowlistProblems,
            'scanned_paths' => $scanned,
        ];
    }

    /**
     * @param list<array{identifier: string, file: string, status: string, reviewed?: string}> $sites
     * @param list<array{identifier: string, file: string, reason: string}> $unknown
     * @param list<string> $scanned
     */
    private function scanPath(string $path, array &$sites, array &$unknown, array &$scanned): void
    {
        $root = realpath($path);
        if ($root === false || ! file_exists($path)) {
            $unknown[] = $this->pathSeam($path, 'configured path does not exist');

            return;
        }
        if (! is_readable($path)) {
            $unknown[] = $this->pathSeam($path, 'configured path is unreadable');

            return;
        }

        $scanned[] = $path;
        if (is_file($root)) {
            $this->scanFile($root, $sites, $unknown);

            return;
        }
        if (! is_dir($root)) {
            $unknown[] = $this->pathSeam($path, 'configured path is neither a file nor a directory');

            return;
        }

        $this->scanDirectory($root, $root, $sites, $unknown);
    }

    /**
     * @param list<array{identifier: string, file: string, status: string, reviewed?: string}> $sites
     * @param list<array{identifier: string, file: string, reason: string}> $unknown
     */
    private function scanDirectory(string $directory, string $root, array &$sites, array &$unknown): void
    {
        try {
            $entries = new FilesystemIterator($directory, FilesystemIterator::SKIP_DOTS);
        } catch (\UnexpectedValueException) {
            $unknown[] = $this->pathSeam($directory, 'configured path is unreadable');

            return;
        }

        foreach ($entries as $entry) {
            if (! $entry instanceof SplFileInfo) {
                continue;
            }
            $path = $entry->getPathname();
            if ($entry->isLink()) {
                $target = realpath($path);
                if ($target === false) {
                    $unknown[] = $this->pathSeam($path, 'symlink target cannot be resolved');

                    continue;
                }
                if (! $this->isWithin($target, $root)) {
                    $unknown[] = $this->pathSeam($path, 'symlink resolves outside configured path');

                    continue;
                }
            }
            if ($entry->isDir()) {
                if (! $entry->isReadable()) {
                    $unknown[] = $this->pathSeam($path, 'path is unreadable');

                    continue;
                }
                $this->scanDirectory($path, $root, $sites, $unknown);

                continue;
            }
            if ($entry->isFile() && pathinfo($path, PATHINFO_EXTENSION) === 'php') {
                if (! $entry->isReadable()) {
                    $unknown[] = $this->pathSeam($path, 'file is unreadable');

                    continue;
                }
                $this->scanFile($path, $sites, $unknown);
            }
        }
    }

    /**
     * @param list<array{identifier: string, file: string, status: string, reviewed?: string}> $sites
     * @param list<array{identifier: string, file: string, reason: string}> $unknown
     */
    private function scanFile(string $file, array &$sites, array &$unknown): void
    {
        $source = file_get_contents($file);
        if ($source === false) {
            $unknown[] = $this->pathSeam($file, 'file is unreadable');

            return;
        }

        $tokens = token_get_all($source);
        $namespace = '';
        $class = null;
        $method = null;
        $pendingClass = null;
        $pendingMethod = null;
        /** @var list<array{class: ?string, method: ?string}> $scopes */
        $scopes = [];

        foreach ($tokens as $index => $token) {
            if (is_string($token)) {
                if ($token === '{') {
                    $scopes[] = ['class' => $pendingClass ?? $class, 'method' => $pendingMethod];
                    $class = $pendingClass ?? $class;
                    $method = $pendingMethod ?? $method;
                    $pendingClass = null;
                    $pendingMethod = null;
                } elseif ($token === '}' && $scopes !== []) {
                    $scope = array_pop($scopes);
                    $class = $scope['class'];
                    $method = $scope['method'];
                }

                continue;
            }

            [$id, $text] = $token;
            if ($id === T_NAMESPACE) {
                $namespace = $this->followingName($tokens, $index);
            } elseif ($id === T_CLASS || $id === T_INTERFACE || $id === T_TRAIT) {
                $name = $this->followingName($tokens, $index);
                $pendingClass = $name === '' ? null : ($namespace === '' ? $name : $namespace . '\\' . $name);
            } elseif ($id === T_FUNCTION) {
                $pendingMethod = $this->followingName($tokens, $index);
                if ($pendingMethod === '') {
                    $pendingMethod = null;
                }
            }

            if ($id === T_STRING && strtolower($text) === 'createtoken') {
                $previous = $this->previousSignificant($tokens, $index);
                $next = $this->nextSignificant($tokens, $index);
                if ($next !== '(') {
                    continue;
                }
                if ($previous === '->' || $previous === '::') {
                    if ($previous === '::' && $this->isVariableClassCall($tokens, $index)) {
                        $unknown[] = $this->seam($this->identifier($class, $method, $file), $file, 'variable class calls createToken');
                    } else {
                        $sites[] = ['identifier' => $this->identifier($class, $method, $file), 'file' => $file, 'status' => 'reported'];
                    }
                }
            }

            if ($id === T_VARIABLE && $this->isDynamicMethodCall($tokens, $index)) {
                $unknown[] = $this->seam($this->identifier($class, $method, $file), $file, 'dynamic method may call createToken');
            }
            if ($id === T_STRING && in_array(strtolower($text), ['call_user_func', 'call_user_func_array'], true)
                && $this->indirectlyNamesCreateToken($tokens, $index)) {
                $unknown[] = $this->seam($this->identifier($class, $method, $file), $file, 'indirect call names createToken');
            }
        }
    }

    /** @param list<int|string|array{int, string, int}> $tokens */
    private function followingName(array $tokens, int $index): string
    {
        $name = '';
        for ($position = $index + 1, $count = count($tokens); $position < $count; $position++) {
            $token = $tokens[$position];
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_FINAL, T_ABSTRACT, T_READONLY], true)) {
                continue;
            }
            if (is_array($token) && in_array($token[0], [T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_NS_SEPARATOR], true)) {
                $name .= $token[1];

                continue;
            }

            break;
        }

        return trim($name, '\\');
    }

    /** @param list<int|string|array{int, string, int}> $tokens */
    private function previousSignificant(array $tokens, int $index): int|string|null
    {
        for ($position = $index - 1; $position >= 0; $position--) {
            $token = $tokens[$position];
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return is_array($token) ? $token[1] : $token;
        }

        return null;
    }

    /** @param list<int|string|array{int, string, int}> $tokens */
    private function nextSignificant(array $tokens, int $index): int|string|null
    {
        for ($position = $index + 1, $count = count($tokens); $position < $count; $position++) {
            $token = $tokens[$position];
            if (is_array($token) && in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            return is_array($token) ? $token[1] : $token;
        }

        return null;
    }

    /** @param list<int|string|array{int, string, int}> $tokens */
    private function isVariableClassCall(array $tokens, int $index): bool
    {
        for ($position = $index - 2; $position >= 0; $position--) {
            $token = $tokens[$position];
            if (is_array($token) && $token[0] === T_WHITESPACE) {
                continue;
            }

            return is_array($token) && $token[0] === T_VARIABLE;
        }

        return false;
    }

    /** @param list<int|string|array{int, string, int}> $tokens */
    private function isDynamicMethodCall(array $tokens, int $index): bool
    {
        return $this->previousSignificant($tokens, $index) === '{'
            && $this->previousSignificant($tokens, $index - 1) === '->'
            && $this->nextSignificant($tokens, $index) === '}'
            && $this->nextSignificant($tokens, $index + 1) === '(';
    }

    /** @param list<int|string|array{int, string, int}> $tokens */
    private function indirectlyNamesCreateToken(array $tokens, int $index): bool
    {
        for ($position = $index + 1, $count = min(count($tokens), $index + 30); $position < $count; $position++) {
            $token = $tokens[$position];
            if (is_array($token) && $token[0] === T_CONSTANT_ENCAPSED_STRING
                && strtolower(trim($token[1], "'\"")) === 'createtoken') {
                return true;
            }
            if ($token === ';') {
                return false;
            }
        }

        return false;
    }

    private function identifier(?string $class, ?string $method, string $file): string
    {
        if ($class !== null && $method !== null) {
            return $class . '::' . $method;
        }

        return $file;
    }

    /** @return array{identifier: string, file: string, reason: string} */
    private function seam(string $identifier, string $file, string $reason): array
    {
        return compact('identifier', 'file', 'reason');
    }

    /** @return array{identifier: string, file: string, reason: string} */
    private function pathSeam(string $path, string $reason): array
    {
        return $this->seam($path, $path, $reason);
    }

    /** @param array<array-key, mixed> $entry */
    private function hasRequiredAllowlistFields(array $entry): bool
    {
        return isset($entry['rationale'], $entry['owner'])
            && is_string($entry['rationale']) && $entry['rationale'] !== ''
            && is_string($entry['owner']) && $entry['owner'] !== '';
    }

    private function isWithin(string $path, string $root): bool
    {
        return $path === $root || str_starts_with($path, $root . DIRECTORY_SEPARATOR);
    }

    /** @return list<array{uri: string}> */
    private function uncoveredRoutes(Router $router): array
    {
        $uncovered = [];
        foreach ($router->getRoutes()->getRoutes() as $route) {
            if (! $this->routeNamesTokenGate(array_values($route->gatherMiddleware()), $router->getMiddlewareGroups())) {
                $uncovered[] = ['uri' => $route->uri()];
            }
        }
        usort($uncovered, static fn (array $left, array $right): int => $left['uri'] <=> $right['uri']);

        return $uncovered;
    }

    /**
     * Route::gatherMiddleware preserves the host's declared groups; expanding
     * those names here keeps host-defined groups visible without treating the
     * package's broad web/api installation as proof a route was intentionally
     * token-gated. A host group that names the alias is concrete coverage.
     *
     * @param list<string> $middleware
     * @param array<string, list<string>> $groups
     */
    private function routeNamesTokenGate(array $middleware, array $groups, bool $direct = true): bool
    {
        foreach ($middleware as $entry) {
            $name = explode(':', $entry, 2)[0];
            if ($name === 'vouch.token' || ($direct && $name === RejectsUnrecordedTokens::class)) {
                return true;
            }
            if (isset($groups[$name]) && $this->routeNamesTokenGate($groups[$name], $groups, false)) {
                return true;
            }
        }

        return false;
    }

    /** @param array{issuance_sites: list<array{identifier: string, file: string, status: string, reviewed?: string}>, unknown_seams: list<array{identifier: string, file: string, reason: string}>, uncovered_routes: list<array{uri: string}>, allowlist_problems: list<array{identifier: string}>, scanned_paths: list<string>} $report */
    private function hasStrictFinding(array $report): bool
    {
        foreach ($report['issuance_sites'] as $site) {
            if ($site['status'] === 'reported') {
                return true;
            }
        }

        return $report['unknown_seams'] !== [] || $report['allowlist_problems'] !== [];
    }

    /** @param array{issuance_sites: list<array{identifier: string, file: string, status: string, reviewed?: string}>, unknown_seams: list<array{identifier: string, file: string, reason: string}>, uncovered_routes: list<array{uri: string}>, allowlist_problems: list<array{identifier: string}>, scanned_paths: list<string>} $report */
    private function render(array $report): void
    {
        $this->table(['Issuance site', 'File', 'Status'], array_map(
            static fn (array $row): array => [$row['identifier'], $row['file'], $row['status']],
            $report['issuance_sites'],
        ));
        $this->table(['Unknown seam', 'File', 'Reason'], array_map(
            static fn (array $row): array => [$row['identifier'], $row['file'], $row['reason']],
            $report['unknown_seams'],
        ));
        $this->table(['Uncovered route'], array_map(static fn (array $row): array => [$row['uri']], $report['uncovered_routes']));
        $this->table(['Allowlist problem'], array_map(static fn (array $row): array => [$row['identifier']], $report['allowlist_problems']));
        $this->components->info('Scanned paths: ' . ($report['scanned_paths'] === [] ? 'none' : implode(', ', $report['scanned_paths'])) . '.');
    }
}
