<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Contracts\TenantResolver;
use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\RecordingAuthThrottleStore;
use Fissible\Vouch\Tests\Support\FailingSharedAuthThrottleStore;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Database\Query\Expression;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function authThrottleBinding(string $suffix = 'default'): string
{
    return SessionBinding::for("auth-throttle-{$suffix}", BindingDomain::Attempt);
}

function authThrottleFlow(?AuthThrottleStore $store = null): AuthFlow
{
    if ($store !== null) {
        app()->instance(AuthThrottleStore::class, $store);
    }

    app()->forgetInstance(AuthFlow::class);

    return app(AuthFlow::class);
}

function authThrottleIdentified(
    AuthFlow $flow,
    string $identifier,
    string $suffix,
    ?string $ip = '203.0.113.5',
): string {
    $binding = authThrottleBinding($suffix);
    $begun = $flow->advance(new FlowRequest(null, 'begin', [], $binding, $ip));
    assert($begun instanceof Continuing && is_string($begun->handle));

    $flow->advance(new FlowRequest(
        $begun->handle,
        'submit',
        ['identifier' => $identifier],
        $binding,
        $ip,
    ));

    return $begun->handle;
}

/** @param array<string, mixed> $input */
function authThrottleSubmit(
    AuthFlow $flow,
    string $handle,
    array $input,
    string $suffix,
    string $action = 'submit',
    ?string $ip = '203.0.113.5',
): \Fissible\Vouch\Flow\FlowResult {
    return $flow->advance(new FlowRequest(
        $handle,
        $action,
        $input,
        authThrottleBinding($suffix),
        $ip,
    ));
}

beforeEach(function (): void {
    AuthPolicy::create([
        'tenant_id' => null,
        'scope' => 'login',
        'document' => ['all_of' => ['password']],
        'posture' => 'strict',
    ]);
    AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)
        ->enroll(7, ['password' => 'a-real-password']);
});

it('advances identical state channels for known and nonexistent identifiers', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:30Z');
    $screens = [];

    foreach (['ada@acme.example', 'nobody@acme.example'] as $index => $identifier) {
        $store = new RecordingAuthThrottleStore();
        $store->recordIdentifierResult = IdentifierThrottle::backedOff(4, $retryAfter);
        $flow = authThrottleFlow($store);
        $suffix = "equal-{$index}";
        $handle = authThrottleIdentified($flow, $identifier, $suffix);
        $result = authThrottleSubmit($flow, $handle, ['password' => 'wrong'], $suffix);
        assert($result instanceof Continuing);

        $operations = array_column($store->calls, 'operation');
        $dimensions = array_map(
            static fn (array $call): array => array_map(
                static fn ($subject): string => $subject instanceof \Fissible\Vouch\Throttle\ThrottleSubject
                    ? $subject->dimension->value
                    : 'integer',
                $call['subjects'],
            ),
            $store->calls,
        );

        expect($operations)->toBe([
            'preflightIdentifier',
            'preflightShared',
            'preflightShared',
            'preflightShared',
            'recordIdentifierFailure',
            'recordIpFailure',
            'recordSharedFailure',
            'recordSharedFailure',
        ])->and($dimensions)->toBe([
            ['identifier'],
            ['ipv4'],
            ['tenant'],
            ['global'],
            ['identifier'],
            ['ipv4', 'ip_identifier'],
            ['tenant'],
            ['global'],
        ]);

        $screens[] = $result->screen;
    }

    expect($screens[0]->errors)->toBe($screens[1]->errors)
        ->and($screens[0]->offeredFactors)->toEqual($screens[1]->offeredFactors)
        ->and($screens[0]->retry)->toEqual($screens[1]->retry)
        ->and($screens[0]->retry?->attemptsRemaining)->toBeNull()
        ->and($screens[0]->retry?->lockedUntil)->toBeNull()
        ->and($screens[0]->retry?->retryAfter)->toBe($retryAfter);
});

it('keys state by the submitted identifier rather than the resolved user', function (): void {
    AuthIdentifier::create([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'ada.secondary@acme.example',
        'verified_at' => now(),
    ]);
    $digests = [];

    foreach (['ada@acme.example', 'ada.secondary@acme.example'] as $index => $identifier) {
        $store = new RecordingAuthThrottleStore();
        $flow = authThrottleFlow($store);
        $suffix = "same-user-{$index}";
        $handle = authThrottleIdentified($flow, $identifier, $suffix);

        authThrottleSubmit($flow, $handle, ['password' => 'wrong'], $suffix);

        $subject = $store->calls[0]['subjects'][0] ?? null;
        assert($subject instanceof \Fissible\Vouch\Throttle\ThrottleSubject);
        $digests[] = $subject->digest;
    }

    expect($digests[0])->not->toBe($digests[1]);
});

it('preflights a lock before verification without incrementing or extending it', function (): void {
    $lockedUntil = new DateTimeImmutable('2026-08-16T12:15:00Z');
    $store = new RecordingAuthThrottleStore();
    $store->preflightIdentifierResult = IdentifierThrottle::locked($lockedUntil);
    $flow = authThrottleFlow($store);
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'locked');
    $result = authThrottleSubmit($flow, $handle, ['password' => 'a-real-password'], 'locked');
    assert($result instanceof Continuing);

    expect(array_column($store->calls, 'operation'))->toBe(['preflightIdentifier'])
        ->and($result->screen->retry?->attemptsRemaining)->toBeNull()
        ->and($result->screen->retry?->lockedUntil)->toBe($lockedUntil)
        ->and($result->screen->errors)->toBe(['Too many attempts. Try again later.']);
});

it('does not increment or extend an active identifier backoff', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:30Z');
    $store = new RecordingAuthThrottleStore();
    $store->preflightIdentifierResult = IdentifierThrottle::backedOff(5, $retryAfter);
    $flow = authThrottleFlow($store);
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'backoff');
    $result = authThrottleSubmit($flow, $handle, ['password' => 'wrong'], 'backoff');
    assert($result instanceof Continuing);

    expect(array_column($store->calls, 'operation'))->toBe(['preflightIdentifier'])
        ->and($result->screen->retry?->retryAfter)->toBe($retryAfter);
});

it('lets a shared dimension back off without fabricating identifier lock state', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:05Z');
    $store = new RecordingAuthThrottleStore();
    $store->preflightSharedResult = SharedThrottle::backedOff($retryAfter);
    $flow = authThrottleFlow($store);
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'shared');
    $result = authThrottleSubmit($flow, $handle, ['password' => 'a-real-password'], 'shared');
    assert($result instanceof Continuing);

    expect(array_column($store->calls, 'operation'))->toBe([
        'preflightIdentifier',
        'preflightShared',
    ])->and($result->screen->retry?->attemptsRemaining)->toBeNull()
        ->and($result->screen->retry?->lockedUntil)->toBeNull()
        ->and($result->screen->retry?->retryAfter)->toBe($retryAfter);
});

it('couples the no-credential equalizer branch to identifier recording', function (): void {
    AuthPolicy::query()->update(['document' => ['any_of' => ['totp']]]);
    AuthCredential::create([
        'user_id' => 7,
        'type' => 'totp',
        'secret' => '',
        'strength' => 'possession',
    ]);
    $store = new RecordingAuthThrottleStore();
    $flow = authThrottleFlow($store);
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'no-credential');

    authThrottleSubmit(
        $flow,
        $handle,
        ['factor' => 'totp', 'code' => '123456'],
        'no-credential',
    );

    expect(array_column($store->calls, 'operation'))
        ->toContain('recordIdentifierFailure');
});

it('skips the IP dimension when the request has no client IP', function (): void {
    $store = new RecordingAuthThrottleStore();
    $flow = authThrottleFlow($store);
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'no-ip', null);

    authThrottleSubmit($flow, $handle, ['password' => 'wrong'], 'no-ip', ip: null);

    expect(array_column($store->calls, 'operation'))->toBe([
        'preflightIdentifier',
        'preflightShared',
        'preflightShared',
        'recordIdentifierFailure',
        'recordSharedFailure',
        'recordSharedFailure',
    ]);
});

it('commits identifier state before propagating a later advisory persistence failure', function (): void {
    $real = app(AuthThrottleStore::class);
    $flow = authThrottleFlow(new FailingSharedAuthThrottleStore($real));
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'schema');

    expect(fn (): mixed => authThrottleSubmit(
        $flow,
        $handle,
        ['password' => 'wrong'],
        'schema',
    ))->toThrow(RuntimeException::class, 'Forced advisory IP persistence failure');

    expect(DB::table('auth_throttle_counters')
        ->where('dimension', ThrottleDimension::Identifier->value)
        ->value('count'))->toBe(1);
});

it('resets identifier state only after full authentication commits', function (): void {
    $flow = authThrottleFlow();
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'reset');

    authThrottleSubmit($flow, $handle, ['password' => 'wrong'], 'reset');
    expect(DB::table('auth_throttle_counters')
        ->where('dimension', ThrottleDimension::Identifier->value)
        ->count())->toBe(1);

    $result = authThrottleSubmit($flow, $handle, ['password' => 'a-real-password'], 'reset');

    expect($result)->toBeInstanceOf(Authenticated::class)
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', ThrottleDimension::Identifier->value)
            ->count())->toBe(0)
        ->and(DB::table('auth_throttle_locks')->count())->toBe(0);
});

it('does not reset after satisfying only the first factor', function (): void {
    AuthPolicy::query()->update(['document' => ['all_of' => ['password', 'totp']]]);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)
        ->enroll(7, ['label' => 'ada@acme.example']);
    $flow = authThrottleFlow();
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'multi');

    authThrottleSubmit($flow, $handle, ['password' => 'wrong'], 'multi');
    $result = authThrottleSubmit($flow, $handle, ['password' => 'a-real-password'], 'multi');

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', ThrottleDimension::Identifier->value)
            ->value('count'))->toBe(1);
});

it('bypasses identifier lock for recovery and leaves login state untouched', function (): void {
    $codes = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)
        ->enroll(7, [])->secrets;
    $code = $codes[0]->reveal();
    $flow = authThrottleFlow();
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'recover');
    $subject = app(ThrottleKey::class)->identifier('ada@acme.example', null);
    $now = new Expression('CURRENT_TIMESTAMP');

    DB::table('auth_throttle_counters')->insert([
        'dimension' => ThrottleDimension::Identifier->value,
        'subject_digest' => $subject->digest,
        'window_started_at' => $now,
        'count' => 10,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
    DB::table('auth_throttle_locks')->insert([
        'subject_digest' => $subject->digest,
        'locked_until' => now()->addMinutes(15),
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    $result = authThrottleSubmit($flow, $handle, ['code' => $code], 'recover', 'recover');

    expect($result)->toBeInstanceOf(RecoveryGraceStarted::class)
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', ThrottleDimension::Identifier->value)
            ->value('count'))->toBe(10)
        ->and(DB::table('auth_throttle_locks')
            ->where('subject_digest', $subject->digest)
            ->count())->toBe(1);
});

it('records a rejected recovery code only in the recovery and shared dimensions', function (): void {
    app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, []);
    $store = new RecordingAuthThrottleStore();
    $flow = authThrottleFlow($store);
    $handle = authThrottleIdentified($flow, 'ada@acme.example', 'recover-failure');

    authThrottleSubmit($flow, $handle, ['code' => 'not-a-code'], 'recover-failure', 'recover');

    $operations = array_column($store->calls, 'operation');
    $recoveryIndex = array_search('recordRecoveryFailure', $operations, true);
    $ipIndex = array_search('recordIpFailure', $operations, true);

    if (! is_int($recoveryIndex) || ! is_int($ipIndex)) {
        throw new RuntimeException('The recovery throttle operations were not recorded.');
    }

    expect($operations)->toContain('recordRecoveryFailure')
        ->and($operations)->not->toContain('recordIdentifierFailure')
        ->and($recoveryIndex)->toBeLessThan($ipIndex);
});

it('persists the host tenant on the attempt before deriving scoped throttle keys', function (): void {
    app()->instance(TenantResolver::class, new class implements TenantResolver
    {
        public function currentTenantId(): string
        {
            return 'tenant-a';
        }
    });
    $flow = authThrottleFlow(new RecordingAuthThrottleStore());
    $result = $flow->advance(new FlowRequest(null, 'begin', [], authThrottleBinding('tenant')));
    assert($result instanceof Continuing && is_string($result->handle));

    expect(AuthAttempt::where('handle', $result->handle)->value('tenant_id'))
        ->toBe('tenant-a');
});
