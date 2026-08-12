<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use FilesystemIterator;
use Generator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * Walks `src/Kernel` and yields its `.php` files as {@see SplFileInfo}
 * instances.
 *
 * `RecursiveIteratorIterator::current()` is typed `mixed` by PHPStan, so
 * every caller that walked the tree by hand had to repeat the same
 * `instanceof`/`isFile()`/extension guard just to get back to a usable
 * type — this centralises that guard once, so PHPStan can verify every
 * caller honestly (no casts, `@var` overrides, or suppressions) instead of
 * each source-scan test re-triggering the same `mixed`-typed errors.
 *
 * Shared by the kernel-boundary source-scan tests (Task 1) and reusable by
 * any later test that needs the same file list — e.g. Task 11's
 * API-surface snapshot test, which walks this same directory.
 *
 * @internal
 */
final class KernelFileWalker
{
    /**
     * @return Generator<int, SplFileInfo>
     */
    public static function phpFiles(): Generator
    {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                dirname(__DIR__, 2) . '/src/Kernel',
                FilesystemIterator::SKIP_DOTS,
            ),
        );

        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo) {
                continue;
            }

            if (! $file->isFile() || $file->getExtension() !== 'php') {
                continue;
            }

            yield $file;
        }
    }
}
