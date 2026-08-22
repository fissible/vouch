<?php

declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

/*
 * The ordinary suite uses file-backed SQLite by default so the concurrency
 * tests exercise one database from their child processes. Hosts and the
 * three-engine matrix may still override this explicitly.
 */
if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite' && getenv('VOUCH_SQLITE_PATH') === false) {
    putenv('VOUCH_SQLITE_PATH=' . sys_get_temp_dir() . '/vouch-test.sqlite');
}

/*
 * Raise the memory limit for MUTATION CHILD PROCESSES ONLY.
 *
 * pest-plugin-mutate launches every mutant as a fresh Symfony Process built from
 * Pest's original arguments plus its own environment variables. A parent-side
 * `php -d memory_limit=…` is not among those arguments, so it cannot propagate —
 * which is why four attempts to raise the limit from outside all truncated at the
 * same point with the stock 128M still in force in the child.
 *
 * The limit must NOT be raised for the ordinary suite. phpunit.xml.dist pins 128M
 * deliberately: SatisfiabilityEvaluatorTest's wide-policy test only *observes* the
 * eager-materialisation regression as a failure when a limit is set, and the guard
 * was calibrated against that exact value. Raising it globally would leave the
 * guard reporting green while no longer guarding — the same silent-loss failure
 * this audit has been finding all along, which is precisely why the fix is scoped
 * rather than convenient.
 *
 * TWO processes need the raise, which cost four diagnostic attempts to separate:
 *
 *  - the mutant CHILDREN, flagged by PEST_MUTATION_TESTING; and
 *  - the ORCHESTRATOR itself. The exhaustion that truncated every earlier attempt
 *    was reported in symfony/process/Pipes/UnixPipes.php — the parent reading its
 *    children's output, not a child. The parent loads this same phpunit.xml.dist,
 *    so it was running the mutation campaign under the 128M pin and died
 *    accumulating results at 12 of 73 files. It carries no PEST_MUTATION_TESTING,
 *    because it is not itself a mutant.
 *
 * So the orchestrator is detected by its own invocation instead. The ordinary
 * suite has no --mutate argument and keeps the pinned 128M.
 *
 * PHPUnit applies its <ini> directives before loading this bootstrap, so this runs
 * after the pin and overrides it only in those two cases.
 */
if (\Fissible\Vouch\Tests\Support\MutationRun::isActive()) {
    ini_set('memory_limit', '4G');
}
