<?php

declare(strict_types=1);

use Illuminate\Support\Facades\DB;

it('boots the service provider and merges config', function (): void {
    expect(config('vouch.recovery_grace.ttl_seconds'))->toBe(900)
        ->and(config('vouch.attempts.ttl_seconds'))->toBe(600);
});

it('connects to the configured test database', function (): void {
    expect(DB::connection()->getPdo())->not->toBeNull();
});
