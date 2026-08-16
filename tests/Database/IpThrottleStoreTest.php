<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleSubject;
use Illuminate\Database\Query\Expression;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function ipThrottleSubject(ThrottleDimension $dimension, int $identity): ThrottleSubject
{
    return new ThrottleSubject(
        $dimension,
        str_pad(dechex($identity), 64, '0', STR_PAD_LEFT),
    );
}

function ipThrottleConfiguration(bool $enforce = false): ThrottleConfiguration
{
    $throttle = config()->array('vouch.throttle');

    if ($enforce) {
        $throttle['ip'] = [
            'mode' => 'enforce',
            'ipv6_observe_at' => 30,
            'ipv4_observe_at' => 300,
            'ipv6_enforce_at' => 2,
            'ipv4_enforce_at' => 3,
            'backoff_seconds' => 5,
        ];
    }

    return ThrottleConfiguration::from(
        $throttle,
        config('vouch.otp.length'),
        config('vouch.totp.digits'),
        config('vouch.totp.window'),
    );
}

function ipThrottleStore(bool $enforce = false): DatabaseAuthThrottleStore
{
    $connection = DB::connection();

    return new DatabaseAuthThrottleStore(
        $connection,
        new DatabaseTime($connection),
        ipThrottleConfiguration($enforce),
    );
}

function ipThrottleTimestamp(mixed $value): DateTimeImmutable
{
    if ($value instanceof DateTimeInterface) {
        return DateTimeImmutable::createFromInterface($value);
    }

    if (is_string($value)) {
        return new DateTimeImmutable($value);
    }

    throw new RuntimeException('The test database returned an invalid IP timestamp.');
}

/** @return array{id: int, windowStartedAt: DateTimeImmutable} */
function ipThrottleParent(ThrottleSubject $ip): array
{
    $raw = DB::table('auth_throttle_ip_windows')
        ->where('dimension', $ip->dimension->value)
        ->where('ip_digest', $ip->digest)
        ->firstOrFail(['id', 'window_started_at']);
    $row = (array) $raw;
    $id = $row['id'] ?? null;
    $started = $row['window_started_at'] ?? null;

    if (! is_int($id)) {
        throw new RuntimeException('The test database returned an invalid IP parent id.');
    }

    return [
        'id' => $id,
        'windowStartedAt' => ipThrottleTimestamp($started),
    ];
}

function currentIpMarkerCount(ThrottleSubject $ip): int
{
    $parent = ipThrottleParent($ip);

    return DB::table('auth_throttle_tuples')
        ->where('ip_window_id', $parent['id'])
        ->where('window_started_at', $parent['windowStartedAt'])
        ->count();
}

it('counts one submitted identifier once per IP window', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $tuple = ipThrottleSubject(ThrottleDimension::IpIdentifier, 2);
    $store = ipThrottleStore();

    $first = $store->recordIpFailure($ip, $tuple);
    $second = $store->recordIpFailure($ip, $tuple);

    expect($first)->toEqual(SharedThrottle::observed())
        ->and($second)->toEqual(SharedThrottle::observed())
        ->and(currentIpMarkerCount($ip))->toBe(1);
});

it('counts distinct submitted identifiers rather than raw failures', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV4, 1);
    $store = ipThrottleStore();

    for ($identity = 1; $identity <= 20; $identity++) {
        $store->recordIpFailure(
            $ip,
            ipThrottleSubject(ThrottleDimension::IpIdentifier, 100 + $identity),
        );
    }

    expect(currentIpMarkerCount($ip))->toBe(20);
});

it('keeps IPv4 and IPv6 parents separate even for an equal digest', function (): void {
    $ipv4 = ipThrottleSubject(ThrottleDimension::IpV4, 1);
    $ipv6 = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $tuple = ipThrottleSubject(ThrottleDimension::IpIdentifier, 2);
    $store = ipThrottleStore();

    $store->recordIpFailure($ipv4, $tuple);
    $store->recordIpFailure($ipv6, $tuple);

    expect(DB::table('auth_throttle_ip_windows')->count())->toBe(2)
        ->and(currentIpMarkerCount($ipv4))->toBe(1)
        ->and(currentIpMarkerCount($ipv6))->toBe(1);
});

it('rolls an expired parent at the exact database boundary and excludes old markers', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $oldTuple = ipThrottleSubject(ThrottleDimension::IpIdentifier, 2);
    $newTuple = ipThrottleSubject(ThrottleDimension::IpIdentifier, 3);
    $now = new Expression('CURRENT_TIMESTAMP');

    $parentId = DB::table('auth_throttle_ip_windows')->insertGetId([
        'dimension' => $ip->dimension->value,
        'ip_digest' => $ip->digest,
        'window_started_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    DB::update(
        'UPDATE auth_throttle_ip_windows SET window_started_at = '
        . (new DatabaseTime(DB::connection()))->deadlineSqlHere()
        . ', updated_at = '
        . (new DatabaseTime(DB::connection()))->deadlineSqlHere()
        . ' WHERE id = ?',
        [-900, -1200, $parentId],
    );
    $oldStart = DB::table('auth_throttle_ip_windows')->where('id', $parentId)
        ->value('window_started_at');
    $oldUpdatedAt = DB::table('auth_throttle_ip_windows')->where('id', $parentId)
        ->value('updated_at');
    DB::table('auth_throttle_tuples')->insert([
        'ip_window_id' => $parentId,
        'window_started_at' => $oldStart,
        'tuple_digest' => $oldTuple->digest,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    ipThrottleStore()->recordIpFailure($ip, $newTuple);
    $parent = ipThrottleParent($ip);

    expect($parent['id'])->toBe($parentId)
        ->and($parent['windowStartedAt']->getTimestamp())
        ->not->toBe(ipThrottleTimestamp($oldStart)->getTimestamp())
        ->and(DB::table('auth_throttle_tuples')->where('ip_window_id', $parentId)->count())
        ->toBe(2)
        ->and(currentIpMarkerCount($ip))->toBe(1)
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $parentId)->value('updated_at'))
        ->not->toBe($oldUpdatedAt);
});

it('recreates an IP parent deleted after the optimistic existence read', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $store = ipThrottleStore();
    $store->recordIpFailure($ip, ipThrottleSubject(ThrottleDimension::IpIdentifier, 2));

    $reads = 0;
    $deleted = false;

    DB::connection()->beforeExecuting(function (string $query) use ($ip, &$reads, &$deleted): void {
        $sql = strtolower(ltrim($query));

        if (! str_starts_with($sql, 'select') || ! str_contains($sql, 'auth_throttle_ip_windows')) {
            return;
        }

        $reads++;

        if ($reads !== 2) {
            return;
        }

        $deleted = DB::table('auth_throttle_ip_windows')
            ->where('dimension', $ip->dimension->value)
            ->where('ip_digest', $ip->digest)
            ->delete() === 1;
    });

    $state = $store->recordIpFailure(
        $ip,
        ipThrottleSubject(ThrottleDimension::IpIdentifier, 3),
    );

    expect($deleted)->toBeTrue()
        ->and($state)->toEqual(SharedThrottle::observed())
        ->and(DB::table('auth_throttle_ip_windows')->count())->toBe(1)
        ->and(currentIpMarkerCount($ip))->toBe(1);
});

it('returns an empty measured state before any IP parent exists', function (bool $enforce): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);

    expect(ipThrottleStore($enforce)->preflightShared($ip))->toEqual(
        $enforce ? SharedThrottle::permitted() : SharedThrottle::observed(),
    );
})->with(['observe' => [false], 'enforce' => [true]]);

it('caps an enforced IP backoff at the fixed-window deadline', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $store = ipThrottleStore(enforce: true);

    $store->recordIpFailure($ip, ipThrottleSubject(ThrottleDimension::IpIdentifier, 2));
    $store->recordIpFailure($ip, ipThrottleSubject(ThrottleDimension::IpIdentifier, 3));
    DB::update(
        'UPDATE auth_throttle_ip_windows SET window_started_at = '
        . (new DatabaseTime(DB::connection()))->deadlineSqlHere()
        . ' WHERE ip_digest = ?',
        [-898, $ip->digest],
    );

    $parent = ipThrottleParent($ip);
    DB::table('auth_throttle_tuples')
        ->where('ip_window_id', $parent['id'])
        ->update(['window_started_at' => $parent['windowStartedAt']]);
    $state = $store->preflightShared($ip);

    expect($state->decision)->toBe(ThrottleDecision::BackedOff)
        ->and($state->retryAfter?->getTimestamp())->toBe(
            $parent['windowStartedAt']->modify('+900 seconds')->getTimestamp(),
        );
});

it('observes threshold crossings without refusing in the shipped mode', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $store = ipThrottleStore();
    $state = null;

    for ($identity = 1; $identity <= 30; $identity++) {
        $state = $store->recordIpFailure(
            $ip,
            ipThrottleSubject(ThrottleDimension::IpIdentifier, 100 + $identity),
        );
    }

    expect($state)->toEqual(SharedThrottle::observed())
        ->and($store->preflightShared($ip))->toEqual(SharedThrottle::observed())
        ->and(currentIpMarkerCount($ip))->toBe(30);
});

it('backs off on a measured distinct-subject crossing without extending it', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $first = ipThrottleSubject(ThrottleDimension::IpIdentifier, 2);
    $second = ipThrottleSubject(ThrottleDimension::IpIdentifier, 3);
    $third = ipThrottleSubject(ThrottleDimension::IpIdentifier, 4);
    $store = ipThrottleStore(enforce: true);

    expect($store->recordIpFailure($ip, $first)->decision)
        ->toBe(ThrottleDecision::Permitted);

    $crossing = $store->recordIpFailure($ip, $second);
    $preflight = $store->preflightShared($ip);
    $before = DB::table('auth_throttle_tuples')->max('created_at');
    $blocked = $store->recordIpFailure($ip, $third);
    $after = DB::table('auth_throttle_tuples')->max('created_at');

    expect($crossing->decision)->toBe(ThrottleDecision::BackedOff)
        ->and($crossing->retryAfter)->not->toBeNull()
        ->and($preflight)->toEqual($crossing)
        ->and($blocked)->toEqual($crossing)
        ->and($after)->toBe($before)
        ->and(currentIpMarkerCount($ip))->toBe(2);
});

it('records a new distinct subject after the measured IP backoff passes', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV6, 1);
    $store = ipThrottleStore(enforce: true);

    $store->recordIpFailure($ip, ipThrottleSubject(ThrottleDimension::IpIdentifier, 2));
    $store->recordIpFailure($ip, ipThrottleSubject(ThrottleDimension::IpIdentifier, 3));

    DB::update(
        'UPDATE auth_throttle_tuples SET created_at = '
        . (new DatabaseTime(DB::connection()))->deadlineSqlHere(),
        [-6],
    );

    $state = $store->recordIpFailure(
        $ip,
        ipThrottleSubject(ThrottleDimension::IpIdentifier, 4),
    );

    expect($state->decision)->toBe(ThrottleDecision::BackedOff)
        ->and(currentIpMarkerCount($ip))->toBe(3);
});

it('keeps IP markers when full authentication resets identifier state', function (): void {
    $ip = ipThrottleSubject(ThrottleDimension::IpV4, 1);
    $tuple = ipThrottleSubject(ThrottleDimension::IpIdentifier, 2);
    $identifier = ipThrottleSubject(ThrottleDimension::Identifier, 3);
    $store = ipThrottleStore();

    $store->recordIpFailure($ip, $tuple);
    $store->recordIdentifierFailure($identifier);
    $store->resetIdentifier($identifier);

    expect(currentIpMarkerCount($ip))->toBe(1);
});

it('rejects each mismatched IP and tuple dimension', function (
    ThrottleDimension $ipDimension,
    ThrottleDimension $tupleDimension,
    string $rejected,
): void {
    $ip = ipThrottleSubject($ipDimension, 1);
    $tuple = ipThrottleSubject($tupleDimension, 2);

    expect(fn (): SharedThrottle => ipThrottleStore()->recordIpFailure($ip, $tuple))
        ->toThrow(InvalidArgumentException::class, 'dimension "' . $rejected . '"');
})->with([
    'IP position' => [ThrottleDimension::Identifier, ThrottleDimension::IpIdentifier, 'identifier'],
    'tuple position' => [ThrottleDimension::IpV6, ThrottleDimension::Identifier, 'identifier'],
]);
