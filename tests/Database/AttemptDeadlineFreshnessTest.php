<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * #44, the freshness half. A deadline can be on the right clock and still be
 * wrong, if the reading is old.
 *
 * The skew tests next door cannot see this. They resolve the flow and begin an
 * attempt in the same breath, so a writer that read database time once and
 * cached it measures correctly there -- it passed every one of those, on both
 * engines. What distinguishes a cached reading from a fresh one is elapsed
 * time, and nothing else.
 *
 * DatabaseMigrations rather than RefreshDatabase, which is the whole reason
 * this lives in its own file. PostgreSQL's CURRENT_TIMESTAMP is the
 * TRANSACTION's start time, so inside RefreshDatabase's wrapping transaction
 * the database clock does not advance no matter how long the test waits, and
 * this test would pass against the defect it exists to catch.
 *
 * The wait is real and the suite pays for it once. Three seconds, against a
 * bracket that already tolerates one, so the margin is the signal rather than
 * the rounding.
 */

const FRESHNESS_TTL = 91;
const FRESHNESS_WAIT = 3;

function freshnessBinding(): string
{
    return str_repeat('f', 64);
}

function freshnessDatabaseNow(): DateTimeImmutable
{
    return app(DatabaseTime::class)->current();
}

function beginFreshnessAttempt(): string
{
    $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], freshnessBinding()));

    if (! $begun instanceof Continuing) {
        throw new RuntimeException('The flow refused to begin an attempt.');
    }

    return stringValue($begun->handle);
}

it('dates the window from the write, not from whenever the clock was last read', function (): void {
    Config::set('vouch.attempts.ttl_seconds', FRESHNESS_TTL);
    app()->forgetInstance(AuthFlow::class);

    /*
     * Resolve everything FIRST, so any reading taken at construction is as old
     * as the wait. A writer that reads the database clock when the INSERT runs
     * is unaffected by this; one that cached a reading is exactly three seconds
     * short, and short is the direction that denies service.
     */
    app(AuthFlow::class);
    app(DatabaseTime::class);

    /*
     * And begin one attempt before the wait, which is not redundant with
     * resolving the services. A writer that caches database time on its FIRST
     * begin rather than at construction initialises that cache here instead of
     * after the wait -- without this line it caches a fresh reading and passes,
     * measured on both engines. The attempt itself is discarded; only the
     * side effect of having run once matters.
     */
    beginFreshnessAttempt();

    $startedAt = freshnessDatabaseNow();
    sleep(FRESHNESS_WAIT);

    $before = freshnessDatabaseNow();
    $handle = beginFreshnessAttempt();
    $after = freshnessDatabaseNow();

    $stored = (new DateTimeImmutable(stringValue(
        DB::table('auth_attempts')->where('handle', $handle)->value('expires_at'),
    )))->getTimestamp();

    /*
     * The same bracket the skew tests use. It is the elapsed wait, not the
     * tolerance, that does the work here: a three-second-old reading misses the
     * lower bound by two seconds even after the one second of slack.
     */
    expect($stored)->toBeGreaterThanOrEqual($before->getTimestamp() + FRESHNESS_TTL - 1)
        ->and($stored)->toBeLessThanOrEqual($after->getTimestamp() + FRESHNESS_TTL + 1);

    /*
     * The premise, asserted rather than assumed: the DATABASE's clock really
     * advanced across the wait. Inside a wrapping transaction on PostgreSQL it
     * would not have, and this test would then pass against the very writer it
     * exists to catch -- a silent pass being worse here than a failure.
     */
    expect($before->getTimestamp() - $startedAt->getTimestamp())
        ->toBeGreaterThanOrEqual(FRESHNESS_WAIT - 1);
});
