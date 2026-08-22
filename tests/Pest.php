<?php

declare(strict_types=1);

/*
 * Database-backed suites boot Testbench. Kernel and Arch suites deliberately
 * do NOT — they are framework-free and must stay fast and unaffected by
 * anything Laravel does.
 */
uses(\Fissible\Vouch\Tests\TestCase::class)->in('Database', 'Concurrency', 'Factors', 'Flow', 'Sessions', 'Http', 'Recovery', 'Console');
