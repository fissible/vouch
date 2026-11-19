<?php

declare(strict_types=1);

use Fissible\Vouch\Support\LockBucketSecret;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Config;

uses(RefreshDatabase::class);

/*
 * #16. A rotation overlap is a state the operator must finish, so the doctor
 * reports it. It is not a misconfiguration, so it must not fail the exit code.
 */

it('reports no rotation row when no previous secret is set', function (): void {
    expect(doctorRows())->not->toHaveKey(LockBucketSecret::PREVIOUS_KEY);
});

it('reports a rotating row that does not count as missing', function (): void {
    $baseline = doctorMissingCount();

    Config::set(LockBucketSecret::PREVIOUS_KEY, str_repeat('p', 40));

    // Premise: the overlap is actually configured, so the row below is not a
    // status the doctor would print regardless.
    expect(LockBucketSecret::overlapConfigured())->toBeTrue()
        ->and(doctorStatus(LockBucketSecret::PREVIOUS_KEY))->toBe('rotating')
        ->and(doctorMissingCount())->toBe($baseline);
});

it('reports a previous secret too short to be one as missing', function (): void {
    $baseline = doctorMissingCount();

    Config::set(LockBucketSecret::PREVIOUS_KEY, 'x');

    expect(doctorStatus(LockBucketSecret::PREVIOUS_KEY))->toBe('missing')
        ->and(doctorMissingCount())->toBe($baseline + 1)
        // The current secret is unaffected; only the overlap is wrong.
        ->and(doctorStatus(LockBucketSecret::KEY))->toBe('pass');
});

it('refuses boot on a previous secret too short to be one', function (): void {
    $original = $_SERVER['argv'] ?? null;

    try {
        $_SERVER['argv'] = ['artisan', 'vouch:other'];

        // Control: the healthy configuration boots, so the refusal below is
        // caused by the previous secret and nothing else.
        (new VouchServiceProvider(app()))->boot();

        Config::set(LockBucketSecret::PREVIOUS_KEY, 'x');

        expect(static fn (): null => (new VouchServiceProvider(app()))->boot())
            ->toThrow(RuntimeException::class, 'VOUCH_LOCK_BUCKETS_PREVIOUS_SECRET');
    } finally {
        if ($original === null) {
            unset($_SERVER['argv']);
        } else {
            $_SERVER['argv'] = $original;
        }
    }
});
