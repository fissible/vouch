<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Tests\Support\RecordingAuthThrottleStore;
use Fissible\Vouch\Throttle\ChallengeAttemptDecision;
use Fissible\Vouch\Throttle\DatabaseAuthThrottleStore;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleDecision;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleSubject;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function contractSubject(ThrottleDimension $dimension): ThrottleSubject
{
    $hex = dechex(array_search($dimension, ThrottleDimension::cases(), true) + 1);

    return new ThrottleSubject($dimension, str_pad($hex, 64, '0', STR_PAD_LEFT));
}

it('carries the exact persisted dimensions without open strings', function (): void {
    expect(array_map(
        static fn (ThrottleDimension $dimension): array => [$dimension->name, $dimension->value],
        ThrottleDimension::cases(),
    ))->toBe([
        ['Identifier', 'identifier'],
        ['Recovery', 'recovery'],
        ['Issuance', 'issuance'],
        ['IpV4', 'ipv4'],
        ['IpV6', 'ipv6'],
        ['IpIdentifier', 'ip_identifier'],
        ['Tenant', 'tenant'],
        ['Global', 'global'],
    ]);
});

it('makes every public persistence subject typed rather than raw', function (): void {
    $reflection = new ReflectionClass(AuthThrottleStore::class);
    $subjectParameters = [];

    foreach ($reflection->getMethods() as $method) {
        foreach ($method->getParameters() as $parameter) {
            if ($parameter->getName() === 'challengeId') {
                continue;
            }

            $type = $parameter->getType();

            $subjectParameters[$method->getName() . ':' . $parameter->getName()] =
                $type instanceof ReflectionNamedType ? $type->getName() : null;
        }
    }

    expect($subjectParameters)->not->toBeEmpty();

    foreach ($subjectParameters as $name => $type) {
        expect($type)->toBe(
            ThrottleSubject::class,
            "{$name} accepts something other than a derived throttle subject.",
        );
    }
});

it('models each identifier state without invalid nullable combinations', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16 12:00:05');
    $lockedUntil = new DateTimeImmutable('2026-08-16 12:15:00');

    expect(get_object_vars(IdentifierThrottle::permitted(5)))->toBe([
        'decision' => ThrottleDecision::Permitted,
        'attemptsRemaining' => 5,
        'lockedUntil' => null,
        'retryAfter' => null,
    ])->and(get_object_vars(IdentifierThrottle::backedOff(4, $retryAfter)))->toBe([
        'decision' => ThrottleDecision::BackedOff,
        'attemptsRemaining' => 4,
        'lockedUntil' => null,
        'retryAfter' => $retryAfter,
    ])->and(get_object_vars(IdentifierThrottle::locked($lockedUntil)))->toBe([
        'decision' => ThrottleDecision::Locked,
        'attemptsRemaining' => 0,
        'lockedUntil' => $lockedUntil,
        'retryAfter' => null,
    ]);
});

it('refuses a negative remaining-attempt count', function (string $factory): void {
    $call = $factory === 'permitted'
        ? fn (): IdentifierThrottle => IdentifierThrottle::permitted(-1)
        : fn (): IdentifierThrottle => IdentifierThrottle::backedOff(
            -1,
            new DateTimeImmutable('2026-08-16 12:00:05'),
        );

    expect($call)->toThrow(InvalidArgumentException::class, 'cannot be negative');
})->with(['permitted', 'backedOff']);

it('permits exactly zero remaining attempts without fabricating a lock', function (): void {
    $state = IdentifierThrottle::permitted(0);

    expect($state->decision)->toBe(ThrottleDecision::Permitted)
        ->and($state->attemptsRemaining)->toBe(0)
        ->and($state->lockedUntil)->toBeNull()
        ->and($state->retryAfter)->toBeNull();
});

it('makes shared state structurally incapable of carrying a lock or attempts', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16 12:00:05');
    $states = [
        SharedThrottle::observed(),
        SharedThrottle::permitted(),
        SharedThrottle::backedOff($retryAfter),
        SharedThrottle::skipped(),
    ];

    expect(array_map(
        static fn (SharedThrottle $state): array => array_keys(get_object_vars($state)),
        $states,
    ))->each->toBe(['decision', 'retryAfter'])
        ->and(array_map(
            static fn (SharedThrottle $state): ThrottleDecision => $state->decision,
            $states,
        ))->toBe([
            ThrottleDecision::Observed,
            ThrottleDecision::Permitted,
            ThrottleDecision::BackedOff,
            ThrottleDecision::Skipped,
        ])
        ->and($states[2]->retryAfter)->toBe($retryAfter);
});

it('keeps every write operation distinct in the recording contract', function (): void {
    $store = new RecordingAuthThrottleStore();
    $identifier = contractSubject(ThrottleDimension::Identifier);
    $recovery = contractSubject(ThrottleDimension::Recovery);
    $ip = contractSubject(ThrottleDimension::IpV4);
    $tuple = contractSubject(ThrottleDimension::IpIdentifier);
    $tenant = contractSubject(ThrottleDimension::Tenant);
    $issuance = contractSubject(ThrottleDimension::Issuance);

    $store->preflightIdentifier($identifier);
    $store->preflightShared($ip);
    $store->recordIdentifierFailure($identifier);
    $store->recordRecoveryFailure($recovery);
    $store->recordIpFailure($ip, $tuple);
    $store->recordSharedFailure($tenant);
    $store->resetIdentifier($identifier);
    $challenge = $store->recordChallengeFailure(42);
    $permission = $store->permitIssuance($issuance);

    expect(array_column($store->calls, 'operation'))->toBe([
        'preflightIdentifier',
        'preflightShared',
        'recordIdentifierFailure',
        'recordRecoveryFailure',
        'recordIpFailure',
        'recordSharedFailure',
        'resetIdentifier',
        'recordChallengeFailure',
        'permitIssuance',
    ])->and($challenge)->toBe(ChallengeAttemptDecision::Remaining)
        ->and($permission)->toBe(IssuancePermission::Permitted);
});

it('permits a recovery bucket when its fixed window has expired', function (): void {
    $subject = contractSubject(ThrottleDimension::Recovery);
    $store = app(DatabaseAuthThrottleStore::class);

    $store->recordRecoveryFailure($subject);
    DB::table('auth_throttle_counters')
        ->where('dimension', ThrottleDimension::Recovery->value)
        ->where('subject_digest', $subject->digest)
        ->update(['window_started_at' => now()->subDay()]);

    expect($store->preflightShared($subject))->toEqual(SharedThrottle::permitted());
});

it('exposes no candidate lookup or digest-returning operation', function (): void {
    $methods = (new ReflectionClass(AuthThrottleStore::class))->getMethods();

    foreach ($methods as $method) {
        $name = strtolower($method->getName());

        expect($name)->not->toContain('lookup');
        expect($name)->not->toContain('find');
        expect($name)->not->toContain('digest');

        $return = $method->getReturnType();

        expect($return instanceof ReflectionNamedType ? $return->getName() : null)
            ->not->toBe('string');
    }
});
