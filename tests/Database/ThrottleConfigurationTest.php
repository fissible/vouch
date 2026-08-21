<?php

declare(strict_types=1);

use Fissible\Vouch\Throttle\ThrottleConfiguration;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Arr;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function throttleConfigArray(): array
{
    $value = config('vouch.throttle');

    if (! is_array($value)) {
        throw new RuntimeException('The shipped vouch.throttle config is not an array.');
    }

    /** @var array<string, mixed> $value */
    return $value;
}

/** @param array<string, mixed> $overrides */
function configuredThrottle(array $overrides = []): ThrottleConfiguration
{
    $config = throttleConfigArray();

    foreach ($overrides as $path => $value) {
        Arr::set($config, $path, $value);
    }

    return ThrottleConfiguration::from(
        $config,
        config('vouch.otp.length'),
        config('vouch.totp.digits'),
        config('vouch.totp.window'),
    );
}

it('reads every shipped default without a caller passing one', function (): void {
    $config = app(ThrottleConfiguration::class);

    expect($config->windowSeconds)->toBe(900)
        ->and($config->retentionSeconds)->toBe(86_400)
        ->and($config->backoffAfter)->toBe(5)
        ->and($config->lockAfter)->toBe(10)
        ->and($config->backoffBase)->toBe(2)
        ->and($config->initialBackoffSeconds)->toBe(1)
        ->and($config->backoffCapSeconds)->toBe(60)
        ->and($config->lockDurationSeconds)->toBe(900)
        ->and($config->challengeAttempts)->toBe(5)
        ->and($config->issuancesPerIdentifier)->toBe(5)
        ->and($config->ipMode)->toBe('observe')
        ->and($config->ipv6ObserveAt)->toBe(30)
        ->and($config->ipv4ObserveAt)->toBe(300)
        ->and($config->ipv6EnforceAt)->toBeNull()
        ->and($config->ipv4EnforceAt)->toBeNull()
        ->and($config->ipBackoffSeconds)->toBeNull()
        ->and($config->tenantMode)->toBe('observe')
        ->and($config->tenantEnforceAt)->toBeNull()
        ->and($config->tenantBackoffSeconds)->toBeNull()
        ->and($config->globalMode)->toBe('observe')
        ->and($config->globalEnforceAt)->toBeNull()
        ->and($config->globalBackoffSeconds)->toBeNull()
        ->and(ThrottleConfiguration::MAX_LOCK_DURATION_SECONDS)->toBe(3_600);
});

it('hydrates CAPTCHA enablement as an explicit boolean', function (): void {
    $config = configuredThrottle([
        'captcha.enabled' => true,
        'global.mode' => 'enforce',
        'global.enforce_at' => 10,
        'global.backoff_seconds' => 1,
    ]);

    expect($config->captchaEnabled)->toBeTrue();
});

it('rejects CAPTCHA enablement when no shared dimension can escalate', function (): void {
    expect(fn (): ThrottleConfiguration => configuredThrottle([
        'captcha.enabled' => true,
    ]))->toThrow(
        InvalidArgumentException::class,
        'vouch.throttle.captcha.enabled',
    );
});

it('accepts explicit numeric environment strings and returns typed values', function (): void {
    $config = configuredThrottle([
        'window_seconds' => '1200',
        'retention_seconds' => '4800',
        'identifier.backoff_after' => '6',
        'identifier.lock_after' => '12',
        'identifier.backoff_base' => '3',
        'identifier.initial_backoff_seconds' => '2',
        'identifier.backoff_cap_seconds' => '90',
        'identifier.lock_duration_seconds' => '1200',
        'challenge.attempts' => '4',
        'challenge.issuances_per_identifier' => '6',
        'ip.ipv6_observe_at' => '40',
        'ip.ipv4_observe_at' => '400',
    ]);

    expect($config->windowSeconds)->toBe(1_200)
        ->and($config->retentionSeconds)->toBe(4_800)
        ->and($config->lockAfter)->toBe(12)
        ->and($config->backoffBase)->toBe(3)
        ->and($config->challengeAttempts)->toBe(4)
        ->and($config->ipv4ObserveAt)->toBe(400);
});

it('accepts the smallest positive environment integer without tightening it', function (): void {
    $config = configuredThrottle(['identifier.initial_backoff_seconds' => '1']);

    expect($config->initialBackoffSeconds)->toBe(1);
});

it('rejects an overflowing numeric environment string as configuration rather than a type error', function (): void {
    $overflow = str_repeat('9', 100);

    expect(fn (): ThrottleConfiguration => configuredThrottle(['window_seconds' => $overflow]))
        ->toThrow(
            InvalidArgumentException::class,
            'Configuration "vouch.throttle.window_seconds" must be a positive integer; got string',
        );

    expect(fn (): ThrottleConfiguration => ThrottleConfiguration::from(
        throttleConfigArray(),
        config('vouch.otp.length'),
        config('vouch.totp.digits'),
        $overflow,
    ))->toThrow(
        InvalidArgumentException::class,
        'Configuration "vouch.totp.window" must be a non-negative integer; got string',
    );
});

it('accepts zero for the TOTP window in both native and environment forms', function (int|string $value): void {
    $config = ThrottleConfiguration::from(
        throttleConfigArray(),
        config('vouch.otp.length'),
        config('vouch.totp.digits'),
        $value,
    );

    expect($config)->toBeInstanceOf(ThrottleConfiguration::class);
})->with(['native zero' => [0], 'environment zero' => ['0']]);

it('rejects every non-negative TOTP-window lookalike with its value type', function (
    mixed $value,
    string $description,
): void {
    expect(fn (): ThrottleConfiguration => ThrottleConfiguration::from(
        throttleConfigArray(),
        config('vouch.otp.length'),
        config('vouch.totp.digits'),
        $value,
    ))->toThrow(
        InvalidArgumentException::class,
        'Configuration "vouch.totp.window" must be a non-negative integer; got ' . $description,
    );
})->with([
    'negative integer' => [-1, '-1'],
    'blank environment value' => ['', 'an empty string'],
    'signed string' => ['+1', 'string "+1"'],
    'leading zero string' => ['01', 'string "01"'],
    'boolean' => [true, 'bool'],
    'null' => [null, 'null'],
]);

it('rejects zero and negative required values with the exact key', function (string $path): void {
    foreach ([0, -1] as $invalid) {
        expect(fn (): ThrottleConfiguration => configuredThrottle([$path => $invalid]))
            ->toThrow(
                InvalidArgumentException::class,
                'Configuration "vouch.throttle.' . $path . '" must be a positive integer',
            );
    }
})->with([
    'window' => ['window_seconds'],
    'retention' => ['retention_seconds'],
    'backoff after' => ['identifier.backoff_after'],
    'lock after' => ['identifier.lock_after'],
    'backoff base' => ['identifier.backoff_base'],
    'initial backoff' => ['identifier.initial_backoff_seconds'],
    'backoff cap' => ['identifier.backoff_cap_seconds'],
    'lock duration' => ['identifier.lock_duration_seconds'],
    'challenge attempts' => ['challenge.attempts'],
    'issuance limit' => ['challenge.issuances_per_identifier'],
    'ipv6 observation' => ['ip.ipv6_observe_at'],
    'ipv4 observation' => ['ip.ipv4_observe_at'],
]);

it('rejects a set-but-blank numeric environment value with the exact key', function (string $path): void {
    expect(fn (): ThrottleConfiguration => configuredThrottle([$path => '']))
        ->toThrow(
            InvalidArgumentException::class,
            'Configuration "vouch.throttle.' . $path
            . '" must be a positive integer; got an empty string.',
        );
})->with([
    'window' => ['window_seconds'],
    'retention' => ['retention_seconds'],
    'backoff after' => ['identifier.backoff_after'],
    'lock after' => ['identifier.lock_after'],
    'backoff base' => ['identifier.backoff_base'],
    'initial backoff' => ['identifier.initial_backoff_seconds'],
    'backoff cap' => ['identifier.backoff_cap_seconds'],
    'lock duration' => ['identifier.lock_duration_seconds'],
    'challenge attempts' => ['challenge.attempts'],
    'issuance limit' => ['challenge.issuances_per_identifier'],
    'ipv6 observation' => ['ip.ipv6_observe_at'],
    'ipv4 observation' => ['ip.ipv4_observe_at'],
]);

it('pins every relational boundary from both sides', function (
    array $valid,
    array $invalid,
    string $message,
): void {
    expect(configuredThrottle($valid))->toBeInstanceOf(ThrottleConfiguration::class);

    expect(fn (): ThrottleConfiguration => configuredThrottle($invalid))
        ->toThrow(InvalidArgumentException::class, $message);
})->with([
    'backoff before lock' => [
        ['identifier.backoff_after' => 9],
        ['identifier.backoff_after' => 10],
        'backoff_after" must be less than',
    ],
    'exponential base' => [
        ['identifier.backoff_base' => 2],
        ['identifier.backoff_base' => 1],
        'backoff_base" must be at least 2',
    ],
    'backoff cap in window' => [
        ['identifier.backoff_cap_seconds' => 900],
        ['identifier.backoff_cap_seconds' => 901],
        'backoff_cap_seconds" must be less than or equal',
    ],
    'wait-out-able lock' => [
        ['identifier.lock_duration_seconds' => 3_600],
        ['identifier.lock_duration_seconds' => 3_601],
        'must not exceed 3600 seconds',
    ],
    'retention correctness floor' => [
        ['retention_seconds' => 4_500],
        ['retention_seconds' => 4_499],
        'retention_seconds" must be at least',
    ],
    'IPv4 observation above IPv6' => [
        ['ip.ipv4_observe_at' => 31],
        ['ip.ipv4_observe_at' => 30],
        'ipv4_observe_at" must be greater than',
    ],
]);

it('requires a complete explicit IP enforcement transition', function (): void {
    $config = configuredThrottle([
        'ip.mode' => 'enforce',
        'ip.ipv6_enforce_at' => 40,
        'ip.ipv4_enforce_at' => 400,
        'ip.backoff_seconds' => 5,
    ]);

    expect($config->ipMode)->toBe('enforce')
        ->and($config->ipv6EnforceAt)->toBe(40)
        ->and($config->ipv4EnforceAt)->toBe(400)
        ->and($config->ipBackoffSeconds)->toBe(5);
});

it('enforces the OTP product against the fixed-boundary guess target', function (): void {
    expect(configuredThrottle([
        'challenge.attempts' => 10,
        'challenge.issuances_per_identifier' => 5,
    ]))->toBeInstanceOf(ThrottleConfiguration::class);

    expect(fn (): ThrottleConfiguration => configuredThrottle([
        'challenge.attempts' => 11,
        'challenge.issuances_per_identifier' => 5,
    ]))->toThrow(InvalidArgumentException::class, 'exceeds the 10^-4 fixed-boundary online-guess target');
});

it('enforces the TOTP drift budget against the fixed-boundary guess target', function (): void {
    expect(configuredThrottle(['identifier.lock_after' => 16]))
        ->toBeInstanceOf(ThrottleConfiguration::class);

    expect(fn (): ThrottleConfiguration => configuredThrottle(['identifier.lock_after' => 17]))
        ->toThrow(InvalidArgumentException::class, 'exceeds the 10^-4 fixed-boundary online-guess target');
});

it('revalidates the target when the factor code space or drift window changes', function (): void {
    $throttle = throttleConfigArray();

    expect(fn (): ThrottleConfiguration => ThrottleConfiguration::from($throttle, 5, 6, 1))
        ->toThrow(InvalidArgumentException::class, 'for "vouch.otp.length"');

    expect(ThrottleConfiguration::from($throttle, 6, 6, 2))
        ->toBeInstanceOf(ThrottleConfiguration::class);

    expect(fn (): ThrottleConfiguration => ThrottleConfiguration::from($throttle, 6, 6, 3))
        ->toThrow(InvalidArgumentException::class, 'for "vouch.totp.digits" and "vouch.totp.window"');
});

it('rejects each missing part of IP enforcement', function (string $path): void {
    $overrides = [
        'ip.mode' => 'enforce',
        'ip.ipv6_enforce_at' => 40,
        'ip.ipv4_enforce_at' => 400,
        'ip.backoff_seconds' => 5,
        $path => null,
    ];

    expect(fn (): ThrottleConfiguration => configuredThrottle($overrides))
        ->toThrow(InvalidArgumentException::class, '"vouch.throttle.' . $path . '" is required');
})->with([
    'IPv6 threshold' => ['ip.ipv6_enforce_at'],
    'IPv4 threshold' => ['ip.ipv4_enforce_at'],
    'backoff' => ['ip.backoff_seconds'],
]);

it('bounds enforced IP delays and preserves the family ordering', function (): void {
    $base = [
        'ip.mode' => 'enforce',
        'ip.ipv6_enforce_at' => 40,
        'ip.ipv4_enforce_at' => 400,
        'ip.backoff_seconds' => 60,
    ];

    expect(configuredThrottle($base))->toBeInstanceOf(ThrottleConfiguration::class);

    expect(fn (): ThrottleConfiguration => configuredThrottle([
        ...$base,
        'ip.backoff_seconds' => 61,
    ]))->toThrow(InvalidArgumentException::class, 'shared-bucket delays stay seconds-scale');

    expect(fn (): ThrottleConfiguration => configuredThrottle([
        ...$base,
        'ip.ipv4_enforce_at' => 40,
    ]))->toThrow(InvalidArgumentException::class, 'ipv4_enforce_at" must be greater than');
});

it('does not arm any IP enforcement value while mode still says observe', function (string $path): void {
    expect(fn (): ThrottleConfiguration => configuredThrottle([$path => 5]))
        ->toThrow(InvalidArgumentException::class, 'until mode is explicitly "enforce"');
})->with([
    'IPv6 threshold' => ['ip.ipv6_enforce_at'],
    'IPv4 threshold' => ['ip.ipv4_enforce_at'],
    'backoff' => ['ip.backoff_seconds'],
]);

it('requires complete tenant and global enforcement independently', function (string $dimension): void {
    if ($dimension !== 'tenant' && $dimension !== 'global') {
        throw new InvalidArgumentException('The test dimension must be tenant or global.');
    }

    $config = configuredThrottle([
        $dimension . '.mode' => 'enforce',
        $dimension . '.enforce_at' => 10_000,
        $dimension . '.backoff_seconds' => 5,
    ]);

    $mode = $dimension === 'tenant' ? $config->tenantMode : $config->globalMode;

    expect($mode)->toBe('enforce');

    foreach (['enforce_at', 'backoff_seconds'] as $missing) {
        expect(fn (): ThrottleConfiguration => configuredThrottle([
            $dimension . '.mode' => 'enforce',
            $dimension . '.enforce_at' => $missing === 'enforce_at' ? null : 10_000,
            $dimension . '.backoff_seconds' => $missing === 'backoff_seconds' ? null : 5,
        ]))->toThrow(
            InvalidArgumentException::class,
            '"vouch.throttle.' . $dimension . '.' . $missing . '" is required',
        );
    }
})->with(['tenant', 'global']);

it('does not arm tenant or global values while their mode still says observe', function (
    string $dimension,
    string $setting,
): void {
    expect(fn (): ThrottleConfiguration => configuredThrottle([
        $dimension . '.' . $setting => 5,
    ]))->toThrow(
        InvalidArgumentException::class,
        'until mode is explicitly "enforce"',
    );
})->with([
    'tenant threshold' => ['tenant', 'enforce_at'],
    'tenant backoff' => ['tenant', 'backoff_seconds'],
    'global threshold' => ['global', 'enforce_at'],
    'global backoff' => ['global', 'backoff_seconds'],
]);

it('bounds tenant and global delays by the identifier backoff cap', function (string $dimension): void {
    $base = [
        $dimension . '.mode' => 'enforce',
        $dimension . '.enforce_at' => 10_000,
    ];

    expect(configuredThrottle([
        ...$base,
        $dimension . '.backoff_seconds' => 60,
    ]))->toBeInstanceOf(ThrottleConfiguration::class);

    expect(fn (): ThrottleConfiguration => configuredThrottle([
        ...$base,
        $dimension . '.backoff_seconds' => 61,
    ]))->toThrow(
        InvalidArgumentException::class,
        'shared-bucket delays stay seconds-scale',
    );
})->with(['tenant', 'global']);

it('rejects invalid or blank shared modes with the exact key', function (string $dimension): void {
    foreach (['', 'enabled', true] as $invalid) {
        expect(fn (): ThrottleConfiguration => configuredThrottle([$dimension . '.mode' => $invalid]))
            ->toThrow(
                InvalidArgumentException::class,
                'Configuration "vouch.throttle.' . $dimension . '.mode" must be exactly',
            );
    }
})->with(['ip', 'tenant', 'global']);

it('has no duplicate fallback when a shipped key disappears', function (): void {
    $config = throttleConfigArray();
    unset($config['window_seconds']);

    expect(fn (): ThrottleConfiguration => ThrottleConfiguration::from($config, 6, 6, 1))
        ->toThrow(
            InvalidArgumentException::class,
            'Missing required configuration key "vouch.throttle.window_seconds"; '
            . 'Vouch has no inline fallback for it.',
        );
});
