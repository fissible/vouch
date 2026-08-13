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

it('publishes the new config sections', function (): void {
    // A key added to config/vouch.php but never merged reads as configurable
    // while silently using a hardcoded default.
    expect(config('vouch.totp.issuer'))->not->toBeNull()
        ->and(config('vouch.otp.ttl_seconds'))->toBeInt()
        ->and(config('vouch.recovery.count'))->toBe(10)
        ->and(config('vouch.enrollment.lock_wait_seconds'))->toBeInt()
        ->and(config('vouch.challenges.require_credential'))->toBe(['email_otp', 'sms_otp']);
});
