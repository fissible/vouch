<?php

declare(strict_types=1);

/*
 * Database-backed suites boot Testbench. Kernel and Arch suites deliberately
 * do NOT — they are framework-free and must stay fast and unaffected by
 * anything Laravel does.
 */
uses(\Fissible\Vouch\Tests\TestCase::class)->in('Database', 'Concurrency', 'Factors', 'Flow', 'Sessions', 'Http', 'Recovery', 'Console', 'Authorization');

/**
 * Narrow a query builder's mixed value to a string without a bare cast.
 *
 * Shared here because Pest test files declare into one global function
 * namespace, so a per-file copy collides at load time.
 */
function stringValue(mixed $value): string
{
    return is_scalar($value) ? (string) $value : '';
}
