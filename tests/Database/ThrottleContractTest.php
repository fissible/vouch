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

/*
 * Note this also freezes declaration ORDER, which is not itself a contract --
 * the persisted values are. It is left as an ordered comparison because the
 * existing test was written that way and reordering cases is not something the
 * package does silently; a set comparison would be the alternative.
 */
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
        /*
         * Added deliberately for 2.3d Task 1. The persisted dimension
         * vocabulary is a schema contract, so extending it is an explicit act:
         * an identifier-control ceremony must not share a counter partition
         * with login issuance, and a boolean flag on ThrottleSubject would
         * leave requireDimension() unable to tell them apart.
         */
        ['Ceremony', 'ceremony'],
        /*
         * #48. Verification redemption is its own authority: a verification code
         * attests control of an identifier, a recovery proof opens a password
         * reset, and a failed guess at one must not spend the other's redemption
         * budget. Extending this vocabulary is the explicit act the note above
         * describes, so the addition is recorded here rather than absorbed.
         *
         * Issuance stays shared between the ceremonies by decision -- both spend
         * the same outbound delivery capacity for one address -- so nothing is
         * added for it.
         */
        ['Verification', 'verification'],
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

/*
 * #48. The store operation is named for what it records.
 *
 * recordRecoveryFailure() guards its dimension, which is why passing a
 * verification subject to it throws rather than silently writing the wrong
 * counter. Reusing that operation and WIDENING the guard to admit verification
 * would pass every behavioural test in the accounting suite while putting two
 * ceremonies' failures through one operation named for one of them -- so the
 * guard is asserted here, where it lives.
 */

it('refuses a verification subject to the recovery recording operation', function (): void {
    $keys = app(\Fissible\Vouch\Throttle\ThrottleKey::class);
    $store = app(\Fissible\Vouch\Contracts\AuthThrottleStore::class);

    expect(fn (): \Fissible\Vouch\Throttle\SharedThrottle => $store->recordRecoveryFailure(
        $keys->verification('person@example.test', null),
    ))->toThrow(InvalidArgumentException::class);
});

it('refuses a recovery subject to the verification recording operation', function (): void {
    $keys = app(\Fissible\Vouch\Throttle\ThrottleKey::class);
    $store = app(\Fissible\Vouch\Contracts\AuthThrottleStore::class);

    // Both ways. A guard that only checked one direction would let the
    // partition leak back through whichever operation was left open.
    expect(fn (): \Fissible\Vouch\Throttle\SharedThrottle => $store->recordVerificationFailure(
        $keys->recovery('person@example.test', null),
    ))->toThrow(InvalidArgumentException::class);
});

it('accepts a verification subject for preflight and recording', function (): void {
    $keys = app(\Fissible\Vouch\Throttle\ThrottleKey::class);
    $store = app(\Fissible\Vouch\Contracts\AuthThrottleStore::class);
    $subject = $keys->verification('person@example.test', null);

    /*
     * The paired positive. Guards that reject everything would satisfy both
     * tests above, and the dimension would be unusable rather than partitioned.
     */
    expect($store->preflightShared($subject)->decision)
        ->toBe(\Fissible\Vouch\Throttle\ThrottleDecision::Permitted)
        ->and($store->recordVerificationFailure($subject))
        ->toBeInstanceOf(\Fissible\Vouch\Throttle\SharedThrottle::class);
});
