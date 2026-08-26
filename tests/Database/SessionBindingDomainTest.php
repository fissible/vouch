<?php

declare(strict_types=1);

use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('derives a different value per domain for the same session', function (): void {
    /*
     * The whole point of the amendment. Without domain separation both columns
     * hold the same value, so a bound_context that escapes into a log or an
     * error message is immediately a valid lookup key into auth_sessions.
     */
    $sessionId = 'the-raw-host-session-id';

    expect(SessionBinding::for($sessionId, BindingDomain::Session))
        ->not->toBe(SessionBinding::for($sessionId, BindingDomain::Attempt));
});

it('stays stable within a domain', function (): void {
    expect(SessionBinding::for('abc', BindingDomain::Attempt))
        ->toBe(SessionBinding::for('abc', BindingDomain::Attempt));
});

it('never contains the raw session id, in either domain', function (): void {
    foreach (BindingDomain::cases() as $domain) {
        expect(SessionBinding::for('raw-id-must-not-appear', $domain))
            ->not->toContain('raw-id-must-not-appear')
            ->and(SessionBinding::for('raw-id-must-not-appear', $domain))->toHaveLength(64);
    }
});

it('still refuses to derive a binding with no APP_KEY', function (): void {
    config(['app.key' => null]);

    SessionBinding::for('abc', BindingDomain::Session);
})->throws(RuntimeException::class);

it('lists every binding domain exactly once', function (): void {
    // Pins the enum so a domain cannot be added without a protocol decision.
    expect(array_map(fn (BindingDomain $d): string => $d->value, BindingDomain::cases()))
        ->toBe([
            'session',
            'attempt',
            'throttle.identifier',
            'throttle.recovery',
            'throttle.issuance',
            'throttle.ipv4',
            'throttle.ipv6-prefix-64',
            'throttle.ip-identifier',
            'throttle.tenant',
            'throttle.global',
            'throttle.ceremony',
        ]);
});

it('pins the complete segmented HMAC protocol with a fixed vector', function (): void {
    config(['app.key' => 'segmented-binding-test-key']);
    $domain = BindingDomain::ThrottleTenant;
    $segments = ['tenant.present', "a\0b"];
    $input = $domain->value . "\0" . pack('N', 2)
        . "\0" . pack('N', strlen($segments[0])) . $segments[0]
        . "\0" . pack('N', strlen($segments[1])) . $segments[1];

    expect(SessionBinding::forSegments($domain, ...$segments))->toBe(
        hash_hmac('sha256', $input, 'segmented-binding-test-key'),
    );
});
