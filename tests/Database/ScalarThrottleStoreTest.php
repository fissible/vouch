<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleSubject;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function scalarThrottleStore(?Connection $connection = null): DatabaseAuthThrottleStore
{
    $connection ??= DB::connection();

    return new DatabaseAuthThrottleStore(
        $connection,
        new DatabaseTime($connection),
        app(ThrottleConfiguration::class),
    );
}

function scalarThrottleSubject(
    ThrottleDimension $dimension = ThrottleDimension::Identifier,
    int $identity = 1,
): ThrottleSubject {
    return new ThrottleSubject(
        $dimension,
        str_pad(dechex($identity), 64, '0', STR_PAD_LEFT),
    );
}

function seedScalarCounter(ThrottleSubject $subject, int $count, int $ageSeconds = 0): void
{
    $connection = DB::connection();
    $now = new \Illuminate\Database\Query\Expression('CURRENT_TIMESTAMP');

    $connection->table('auth_throttle_counters')->insert([
        'dimension' => $subject->dimension->value,
        'subject_digest' => $subject->digest,
        'window_started_at' => $now,
        'count' => $count,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    if ($ageSeconds > 0) {
        $connection->update(
            'UPDATE auth_throttle_counters SET window_started_at = '
            . (new DatabaseTime($connection))->deadlineSqlHere()
            . ' WHERE dimension = ? AND subject_digest = ?',
            [-$ageSeconds, $subject->dimension->value, $subject->digest],
        );
    }
}

function seedScalarLock(ThrottleSubject $subject, int $secondsFromNow): void
{
    $connection = DB::connection();
    $now = new \Illuminate\Database\Query\Expression('CURRENT_TIMESTAMP');

    $connection->table('auth_throttle_locks')->insert([
        'subject_digest' => $subject->digest,
        'locked_until' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    $connection->update(
        'UPDATE auth_throttle_locks SET locked_until = '
        . (new DatabaseTime($connection))->deadlineSqlHere()
        . ' WHERE subject_digest = ?',
        [$secondsFromNow, $subject->digest],
    );
}

function scalarCount(ThrottleSubject $subject): ?int
{
    $value = DB::table('auth_throttle_counters')
        ->where('dimension', $subject->dimension->value)
        ->where('subject_digest', $subject->digest)
        ->value('count');

    return is_int($value) ? $value : null;
}

function scalarTimestamp(mixed $value): DateTimeImmutable
{
    if ($value instanceof DateTimeInterface) {
        return DateTimeImmutable::createFromInterface($value);
    }

    if (is_string($value)) {
        return new DateTimeImmutable($value);
    }

    throw new RuntimeException('The test database returned an invalid timestamp.');
}

function deleteScalarCounterAfterOptimisticRead(ThrottleSubject $subject): Closure
{
    $reads = 0;
    $deleted = false;

    DB::connection()->beforeExecuting(function (string $query) use ($subject, &$reads, &$deleted): void {
        $sql = strtolower(ltrim($query));

        if (! str_starts_with($sql, 'select') || ! str_contains($sql, 'auth_throttle_counters')) {
            return;
        }

        $reads++;

        if ($reads !== 2) {
            return;
        }

        $deleted = DB::table('auth_throttle_counters')
            ->where('dimension', $subject->dimension->value)
            ->where('subject_digest', $subject->digest)
            ->delete() === 1;
    });

    return static function () use (&$deleted): bool {
        return $deleted;
    };
}

it('derives the exact cumulative identifier backoff schedule', function (
    int $count,
    ThrottleDecision $decision,
    int $remaining,
    ?int $offset,
): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, $count);

    $state = scalarThrottleStore()->preflightIdentifier($subject);
    $window = DB::table('auth_throttle_counters')->value('window_started_at');

    expect($state->decision)->toBe($decision)
        ->and($state->attemptsRemaining)->toBe($remaining);

    if ($offset === null) {
        expect($state->retryAfter)->toBeNull();

        return;
    }

    expect($state->retryAfter)->not->toBeNull()
        ->and($state->retryAfter?->getTimestamp())
        ->toBe(scalarTimestamp($window)->modify("+{$offset} seconds")->getTimestamp());
})->with([
    'count 4 has no backoff' => [4, ThrottleDecision::Permitted, 6, null],
    'count 5 backs off to second 1' => [5, ThrottleDecision::BackedOff, 5, 1],
    'count 9 backs off to second 31' => [9, ThrottleDecision::BackedOff, 1, 31],
]);

it('stops incrementing during backoff and resumes only after its database deadline', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 5);

    $blocked = scalarThrottleStore()->recordIdentifierFailure($subject);

    expect($blocked->decision)->toBe(ThrottleDecision::BackedOff)
        ->and(scalarCount($subject))->toBe(5);

    DB::update(
        'UPDATE auth_throttle_counters SET window_started_at = '
        . (new DatabaseTime(DB::connection()))->deadlineSqlHere()
        . ' WHERE subject_digest = ?',
        [-1, $subject->digest],
    );

    $resumed = scalarThrottleStore()->recordIdentifierFailure($subject);

    expect($resumed->decision)->toBe(ThrottleDecision::BackedOff)
        ->and($resumed->attemptsRemaining)->toBe(4)
        ->and(scalarCount($subject))->toBe(6);
});

it('locks exactly at the threshold without extending an active lock', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 9, ageSeconds: 32);

    $locked = scalarThrottleStore()->recordIdentifierFailure($subject);
    $expectedDeadline = DB::scalar(
        'SELECT ' . (new DatabaseTime(DB::connection()))->deadlineSqlHere(),
        [900],
    );

    expect($locked->decision)->toBe(ThrottleDecision::Locked)
        ->and($locked->lockedUntil)->not->toBeNull()
        ->and($locked->lockedUntil?->getTimestamp())
        ->toBe(scalarTimestamp($expectedDeadline)->getTimestamp())
        ->and(scalarCount($subject))->toBe(10);

    DB::update(
        'UPDATE auth_throttle_locks SET locked_until = '
        . (new DatabaseTime(DB::connection()))->deadlineSqlHere()
        . ' WHERE subject_digest = ?',
        [120, $subject->digest],
    );
    $before = DB::table('auth_throttle_locks')->where('subject_digest', $subject->digest)
        ->value('locked_until');

    $again = scalarThrottleStore()->recordIdentifierFailure($subject);
    $after = DB::table('auth_throttle_locks')->where('subject_digest', $subject->digest)
        ->value('locked_until');

    expect($again->decision)->toBe(ThrottleDecision::Locked)
        ->and($after)->toBe($before)
        ->and(scalarCount($subject))->toBe(10);
});

it('uses lock expiry as a sufficient unlock and starts a fresh failure window', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 10, ageSeconds: 120);
    seedScalarLock($subject, 0);
    $oldStart = DB::table('auth_throttle_counters')
        ->where('subject_digest', $subject->digest)
        ->value('window_started_at');

    $preflight = scalarThrottleStore()->preflightIdentifier($subject);
    $recorded = scalarThrottleStore()->recordIdentifierFailure($subject);
    $newStart = DB::table('auth_throttle_counters')
        ->where('subject_digest', $subject->digest)
        ->value('window_started_at');

    expect($preflight)->toEqual(IdentifierThrottle::permitted(10))
        ->and($recorded)->toEqual(IdentifierThrottle::permitted(9))
        ->and(scalarCount($subject))->toBe(1)
        ->and($newStart)->not->toBe($oldStart)
        ->and(DB::table('auth_throttle_locks')->where('subject_digest', $subject->digest)->exists())
        ->toBeFalse();
});

it('preserves the fixed-window epoch on an ordinary identifier increment', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 1, ageSeconds: 120);
    $oldStart = DB::table('auth_throttle_counters')
        ->where('subject_digest', $subject->digest)
        ->value('window_started_at');

    $state = scalarThrottleStore()->recordIdentifierFailure($subject);
    $newStart = DB::table('auth_throttle_counters')
        ->where('subject_digest', $subject->digest)
        ->value('window_started_at');

    expect($state)->toEqual(IdentifierThrottle::permitted(8))
        ->and(scalarCount($subject))->toBe(2)
        ->and($newStart)->toBe($oldStart);
});

it('permits an expired threshold counter without fabricating a lock', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 10, ageSeconds: 900);

    expect(scalarThrottleStore()->preflightIdentifier($subject))
        ->toEqual(IdentifierThrottle::permitted(10));
});

it('reports an active identifier lock directly from its own stored deadline', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 4);
    seedScalarLock($subject, 120);

    $stored = DB::table('auth_throttle_locks')
        ->where('subject_digest', $subject->digest)
        ->value('locked_until');
    $state = scalarThrottleStore()->preflightIdentifier($subject);

    expect($state->decision)->toBe(ThrottleDecision::Locked)
        ->and($state->attemptsRemaining)->toBe(0)
        ->and($state->retryAfter)->toBeNull()
        ->and($state->lockedUntil?->getTimestamp())
        ->toBe(scalarTimestamp($stored)->getTimestamp());
});

it('queries both identifier lock boundaries at the database clock with zero offset', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 4);
    seedScalarLock($subject, 120);
    DB::flushQueryLog();
    DB::enableQueryLog();

    $preflight = scalarThrottleStore()->preflightIdentifier($subject);
    $recorded = scalarThrottleStore()->recordIdentifierFailure($subject);
    $queries = DB::getQueryLog();
    DB::disableQueryLog();
    DB::flushQueryLog();

    $boundaryBindings = array_values(array_map(
        static fn (array $query): mixed => $query['bindings'][1] ?? null,
        array_filter(
            $queries,
            static fn (array $query): bool => str_contains($query['query'], 'auth_throttle_locks')
                && str_contains($query['query'], 'locked_until >'),
        ),
    ));

    expect($preflight->decision)->toBe(ThrottleDecision::Locked)
        ->and($recorded->decision)->toBe(ThrottleDecision::Locked)
        ->and($boundaryBindings)->toBe([0, 0]);
});

it('fails closed when a threshold counter has no lock record', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 10);

    expect(fn (): IdentifierThrottle => scalarThrottleStore()->preflightIdentifier($subject))
        ->toThrow(RuntimeException::class, 'reached its lock threshold without a lock record');
});

it('fails closed on a persisted negative throttle count where the engine permits one', function (): void {
    $subject = scalarThrottleSubject();

    if (in_array(DB::connection()->getDriverName(), ['mysql', 'mariadb'], true)) {
        expect(fn (): bool => DB::table('auth_throttle_counters')->insert([
            'dimension' => $subject->dimension->value,
            'subject_digest' => $subject->digest,
            'window_started_at' => now(),
            'count' => -1,
            'created_at' => now(),
            'updated_at' => now(),
        ]))->toThrow(\Illuminate\Database\QueryException::class);

        return;
    }

    seedScalarCounter($subject, -1);

    expect(fn (): IdentifierThrottle => scalarThrottleStore()->preflightIdentifier($subject))
        ->toThrow(RuntimeException::class, 'invalid throttle count');
});

it('rolls at the exact database-clock window boundary', function (): void {
    $subject = scalarThrottleSubject();
    seedScalarCounter($subject, 4, ageSeconds: 900);
    $oldStart = DB::table('auth_throttle_counters')->value('window_started_at');

    $state = scalarThrottleStore()->recordIdentifierFailure($subject);
    $newStart = DB::table('auth_throttle_counters')->value('window_started_at');

    expect($state)->toEqual(IdentifierThrottle::permitted(9))
        ->and(scalarCount($subject))->toBe(1)
        ->and($newStart)->not->toBe($oldStart);
});

it('caps cumulative recovery backoff at the fixed-window deadline', function (): void {
    $subject = scalarThrottleSubject(ThrottleDimension::Recovery);
    seedScalarCounter($subject, 100);

    $state = scalarThrottleStore()->preflightShared($subject);
    $window = DB::table('auth_throttle_counters')->value('window_started_at');

    expect($state->decision)->toBe(ThrottleDecision::BackedOff)
        ->and($state->retryAfter?->getTimestamp())
        ->toBe(scalarTimestamp($window)->modify('+900 seconds')->getTimestamp());
});

it('pins both sides of the recovery backoff threshold without charging during backoff', function (): void {
    $before = scalarThrottleSubject(ThrottleDimension::Recovery, 1);
    $at = scalarThrottleSubject(ThrottleDimension::Recovery, 2);
    seedScalarCounter($before, 4);
    seedScalarCounter($at, 5);

    // Keep the one-second backoff deadline unambiguously live on slower
    // engines. A test that relies on the insert and assertion sharing one
    // second is a baseline that can pass while the deadline has already
    // elapsed (or fail only because the engine is slower).
    $connection = DB::connection();
    $future = (new DatabaseTime($connection))->deadline(60);
    $connection->table('auth_throttle_counters')
        ->where('dimension', $at->dimension->value)
        ->where('subject_digest', $at->digest)
        ->update(['window_started_at' => $future]);

    $store = scalarThrottleStore();
    $beforeState = $store->preflightShared($before);
    $atState = $store->recordRecoveryFailure($at);

    expect($beforeState)->toEqual(SharedThrottle::permitted())
        ->and($atState->decision)->toBe(ThrottleDecision::BackedOff)
        ->and(scalarCount($at))->toBe(5);
});

it('treats absent and expired shared counters according to their dimension', function (
    ThrottleDimension $dimension,
    SharedThrottle $expected,
): void {
    $absent = scalarThrottleSubject($dimension, 11);
    $expired = scalarThrottleSubject($dimension, 12);
    seedScalarCounter($expired, 100, ageSeconds: 900);
    $store = scalarThrottleStore();

    expect($store->preflightShared($absent))->toEqual($expected)
        ->and($store->preflightShared($expired))->toEqual($expected);
})->with([
    'recovery is permitted' => [ThrottleDimension::Recovery, SharedThrottle::permitted()],
    'tenant is observed' => [ThrottleDimension::Tenant, SharedThrottle::observed()],
    'global is observed' => [ThrottleDimension::Global, SharedThrottle::observed()],
]);

it('recreates a counter deleted after each optimistic existence read', function (
    ThrottleDimension $dimension,
): void {
    $subject = scalarThrottleSubject($dimension, 31);
    seedScalarCounter($subject, 2);
    $wasDeleted = deleteScalarCounterAfterOptimisticRead($subject);
    $store = scalarThrottleStore();

    $state = match ($dimension) {
        ThrottleDimension::Identifier => $store->recordIdentifierFailure($subject),
        ThrottleDimension::Recovery => $store->recordRecoveryFailure($subject),
        default => $store->recordSharedFailure($subject),
    };

    expect($wasDeleted())->toBeTrue()
        ->and(scalarCount($subject))->toBe(1)
        ->and($state->decision)->toBe(
            $dimension === ThrottleDimension::Identifier
                ? ThrottleDecision::Permitted
                : ($dimension === ThrottleDimension::Recovery
                    ? ThrottleDecision::Permitted
                    : ThrottleDecision::Observed),
        );
})->with([
    'identifier' => [ThrottleDimension::Identifier],
    'recovery' => [ThrottleDimension::Recovery],
    'tenant' => [ThrottleDimension::Tenant],
]);

it('observes unarmed tenant and global counters without fabricating backoff', function (
    ThrottleDimension $dimension,
): void {
    $subject = scalarThrottleSubject($dimension);

    $state = scalarThrottleStore()->recordSharedFailure($subject);

    expect($state)->toEqual(SharedThrottle::observed())
        ->and(scalarCount($subject))->toBe(1);
})->with([
    'tenant' => [ThrottleDimension::Tenant],
    'global' => [ThrottleDimension::Global],
]);

it('resets only submitted-identifier failure state', function (): void {
    $identifier = scalarThrottleSubject(ThrottleDimension::Identifier, 1);
    $recovery = scalarThrottleSubject(ThrottleDimension::Recovery, 2);
    $tenant = scalarThrottleSubject(ThrottleDimension::Tenant, 3);

    seedScalarCounter($identifier, 10);
    seedScalarLock($identifier, 600);
    seedScalarCounter($recovery, 2);
    seedScalarCounter($tenant, 3);

    scalarThrottleStore()->resetIdentifier($identifier);

    expect(scalarCount($identifier))->toBeNull()
        ->and(DB::table('auth_throttle_locks')->where('subject_digest', $identifier->digest)->exists())
        ->toBeFalse()
        ->and(scalarCount($recovery))->toBe(2)
        ->and(scalarCount($tenant))->toBe(3);
});

it('treats arbitrary known-looking and unknown-looking subjects identically', function (): void {
    $knownLooking = scalarThrottleSubject(ThrottleDimension::Identifier, 7);
    $unknownLooking = scalarThrottleSubject(ThrottleDimension::Identifier, 8);
    $store = scalarThrottleStore();

    $known = $store->recordIdentifierFailure($knownLooking);
    $unknown = $store->recordIdentifierFailure($unknownLooking);

    expect($known)->toEqual($unknown)
        ->and(scalarCount($knownLooking))->toBe(1)
        ->and(scalarCount($unknownLooking))->toBe(1);
});

it('refuses a dimension at every wrong operation boundary', function (
    Closure $operation,
    string $dimension,
): void {
    expect($operation)->toThrow(
        InvalidArgumentException::class,
        'does not accept dimension "' . $dimension . '"',
    );
})->with([
    'identifier preflight' => [
        fn (): IdentifierThrottle => scalarThrottleStore()->preflightIdentifier(
            scalarThrottleSubject(ThrottleDimension::Recovery),
        ),
        'recovery',
    ],
    'identifier write' => [
        fn (): IdentifierThrottle => scalarThrottleStore()->recordIdentifierFailure(
            scalarThrottleSubject(ThrottleDimension::Recovery),
        ),
        'recovery',
    ],
    'identifier reset' => [
        function (): void {
            scalarThrottleStore()->resetIdentifier(
                scalarThrottleSubject(ThrottleDimension::Recovery),
            );
        },
        'recovery',
    ],
    'recovery write' => [
        fn (): SharedThrottle => scalarThrottleStore()->recordRecoveryFailure(
            scalarThrottleSubject(ThrottleDimension::Identifier),
        ),
        'identifier',
    ],
    'shared preflight' => [
        fn (): SharedThrottle => scalarThrottleStore()->preflightShared(
            scalarThrottleSubject(ThrottleDimension::Identifier),
        ),
        'identifier',
    ],
    'shared write' => [
        fn (): SharedThrottle => scalarThrottleStore()->recordSharedFailure(
            scalarThrottleSubject(ThrottleDimension::Recovery),
        ),
        'recovery',
    ],
]);
