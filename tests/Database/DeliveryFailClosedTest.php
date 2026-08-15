<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Notifications\UnconfiguredOtpDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('refuses to deliver an OTP when no transport is configured', function (): void {
    /*
     * The default binding, and it must throw rather than do nothing.
     *
     * A no-op would make codes silently never arrive -- indistinguishable to the
     * user from a slow mail server, and to the operator from a working system.
     * Logging the code instead would disclose a live credential to whoever reads
     * the logs. Refusing at the point of misconfiguration is the only option that
     * neither hides the fault nor leaks the secret.
     */
    expect(fn () => (new UnconfiguredOtpDelivery())->deliver(
        new AuthIdentifier(['user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example']),
        '123456',
        new DateTimeImmutable('2026-08-14T12:00:00+00:00'),
    ))->toThrow(RuntimeException::class, 'No OTP delivery is configured');
});

it('is what the container resolves until a host binds a transport', function (): void {
    // The refusal only matters if it is the default. A different fallback -- or
    // none -- would change an explicit failure into an unbound-class error or,
    // worse, a silently discarded code.
    expect(app(OtpDelivery::class))->toBeInstanceOf(UnconfiguredOtpDelivery::class);
});
