<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AuthThrottleStore;
use Fissible\Vouch\Throttle\IssuancePermission;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('permits exactly five issuance events in one fixed window', function (): void {
    $store = app(AuthThrottleStore::class);
    $subject = app(ThrottleKey::class)->issuance('ada@acme.example', null);

    for ($event = 1; $event <= 5; $event++) {
        expect($store->permitIssuance($subject))->toBe(IssuancePermission::Permitted);
    }

    expect($store->permitIssuance($subject))->toBe(IssuancePermission::Refused)
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', 'issuance')
            ->where('subject_digest', $subject->digest)
            ->value('count'))->toBe(5);
});

it('rebases an issuance counter only after its database-clock window expires', function (): void {
    $store = app(AuthThrottleStore::class);
    $subject = app(ThrottleKey::class)->issuance('ada@acme.example', null);

    for ($event = 1; $event <= 5; $event++) {
        $store->permitIssuance($subject);
    }

    DB::table('auth_throttle_counters')
        ->where('dimension', 'issuance')
        ->where('subject_digest', $subject->digest)
        ->update(['window_started_at' => now()->subSeconds(901)]);

    expect($store->permitIssuance($subject))->toBe(IssuancePermission::Permitted)
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', 'issuance')
            ->where('subject_digest', $subject->digest)
            ->value('count'))->toBe(1);
});

it('recreates issuance state deleted after the optimistic existence read', function (): void {
    $store = app(AuthThrottleStore::class);
    $subject = app(ThrottleKey::class)->issuance('ada@acme.example', null);

    expect($store->permitIssuance($subject))->toBe(IssuancePermission::Permitted);

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
            ->where('dimension', 'issuance')
            ->where('subject_digest', $subject->digest)
            ->delete() === 1;
    });

    expect($store->permitIssuance($subject))->toBe(IssuancePermission::Permitted)
        ->and($deleted)->toBeTrue()
        ->and(DB::table('auth_throttle_counters')
            ->where('dimension', 'issuance')
            ->where('subject_digest', $subject->digest)
            ->value('count'))->toBe(1);
});

it('refuses to treat another throttle dimension as issuance volume', function (): void {
    $subject = app(ThrottleKey::class)->recovery('ada@acme.example', null);

    expect(fn () => app(AuthThrottleStore::class)->permitIssuance($subject))
        ->toThrow(InvalidArgumentException::class, 'does not accept dimension "recovery"');
});
