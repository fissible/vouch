<?php

declare(strict_types=1);

use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Fissible\Vouch\Throttle\IpCanonicalizer;
use Fissible\Vouch\Throttle\ThrottleKey;

function throttleKey(): ThrottleKey
{
    return new ThrottleKey(new IdentifierCanonicalizer(), new IpCanonicalizer());
}

it('canonicalizes identifier case and Unicode composition before derivation', function (): void {
    $keys = throttleKey();

    expect($keys->identifier("\u{00C9}lodie@example.test", null))
        ->toBe($keys->identifier("E\u{0301}LODIE@example.test", null))
        // Lowercasing J + caron creates a decomposed form that must be
        // normalized again; constructor-time normalization alone cannot pass.
        ->and($keys->identifier("\u{01F0}@example.test", null))
        ->toBe($keys->identifier("J\u{030C}@example.test", null));
});

it('does not apply provider-specific identifier aliases', function (): void {
    $keys = throttleKey();

    expect($keys->identifier('user.name@gmail.com', null))
        ->not->toBe($keys->identifier('username@gmail.com', null));
});

it('distinguishes an absent tenant from an empty tenant', function (): void {
    $keys = throttleKey();

    expect($keys->identifier('person@example.test', null))
        ->not->toBe($keys->identifier('person@example.test', ''));
});

it('frames segments so separator-looking values cannot collide', function (): void {
    expect(SessionBinding::forSegments(
        BindingDomain::ThrottleTenant,
        'a',
        "\0b",
    ))->not->toBe(SessionBinding::forSegments(
        BindingDomain::ThrottleTenant,
        "a\0",
        'b',
    ));
});

it('requires at least one explicit segment', function (): void {
    expect(fn (): string => SessionBinding::forSegments(BindingDomain::ThrottleGlobal))
        ->toThrow(InvalidArgumentException::class, 'at least one explicit segment');
});

it('separates identifier and recovery domains for the same subject', function (): void {
    $keys = throttleKey();

    expect($keys->identifier('person@example.test', 'tenant-a'))
        ->not->toBe($keys->recovery('person@example.test', 'tenant-a'));
});

it('canonicalizes IPv4 and separates distinct addresses', function (): void {
    $keys = throttleKey();
    $canonical = $keys->ip('192.0.2.10', null);
    $roundTrip = $keys->ip((string) inet_ntop((string) inet_pton('192.0.2.10')), null);
    $other = $keys->ip('192.0.2.11', null);

    expect([$canonical, $roundTrip, $other])->each->toBeString()
        ->and($canonical)->toBe($roundTrip)
        ->and($canonical === $other)->toBeFalse();
});

it('treats an IPv4-mapped IPv6 address as its IPv4 subject', function (): void {
    $keys = throttleKey();

    expect($keys->ip('::ffff:192.0.2.10', null))
        ->toBe($keys->ip('192.0.2.10', null));
});

it('buckets equivalent IPv6 text and privacy addresses by 64-bit prefix', function (): void {
    $keys = throttleKey();

    $compressed = $keys->ip('2001:db8:abcd:1234::1', null);
    $expanded = $keys->ip('2001:0db8:abcd:1234:0000:0000:0000:0001', null);
    $privacy = $keys->ip('2001:db8:abcd:1234:deaf:beef:cafe:babe', null);
    $neighbor = $keys->ip('2001:db8:abcd:1235::1', null);

    expect([$compressed, $expanded, $privacy, $neighbor])->each->toBeString()
        ->and($compressed)->toBe($expanded)->toBe($privacy)
        ->and($compressed === $neighbor)->toBeFalse();
});

it('uses canonical IP and identifier segments for tuple markers', function (): void {
    $keys = throttleKey();

    $canonical = $keys->ipIdentifier(
        '2001:db8:abcd:1234::1',
        "\u{00C9}lodie@example.test",
        null,
    );

    expect($canonical)->toBe($keys->ipIdentifier(
        '2001:db8:abcd:1234:ffff:ffff:ffff:ffff',
        "E\u{0301}LODIE@example.test",
        null,
    ))
        ->and($canonical === $keys->ipIdentifier(
            '2001:db8:abcd:1234::1',
            'other@example.test',
            null,
        ))->toBeFalse()
        ->and($canonical === $keys->ipIdentifier(
            '2001:db8:abcd:1235::1',
            "\u{00C9}lodie@example.test",
            null,
        ))->toBeFalse();
});

it('skips the IP dimensions when client IP is absent', function (): void {
    $keys = throttleKey();

    expect($keys->ip(null, null))->toBeNull()
        ->and($keys->ipIdentifier(null, 'person@example.test', null))->toBeNull();
});

it('rejects invalid client IP instead of sharing an unknown bucket', function (): void {
    expect(fn (): ?string => throttleKey()->ip('not-an-ip', null))
        ->toThrow(InvalidArgumentException::class, 'not a valid IP address');
});

it('derives all non-IP throttle dimensions without exposing their subjects', function (): void {
    $keys = throttleKey();
    $raw = 'raw-person@example.test';
    $derived = [
        $keys->identifier($raw, null),
        $keys->recovery($raw, null),
        $keys->tenant(null),
        $keys->tenant('tenant-a'),
        $keys->global(),
    ];
    $ip = $keys->ip('192.0.2.10', null);
    $tuple = $keys->ipIdentifier('192.0.2.10', $raw, null);

    expect([$ip, $tuple])->each->toBeString();

    if ($ip === null || $tuple === null) {
        throw new LogicException('A valid IP must produce IP and tuple throttle keys.');
    }

    $derived[] = $ip;
    $derived[] = $tuple;

    foreach ($derived as $value) {
        expect($value)->toMatch('/\A[0-9a-f]{64}\z/');
        expect(str_contains($value, $raw))->toBeFalse()
            ->and(str_contains($value, 'tenant-a'))->toBeFalse();
    }
});

it('changes throttle keys when APP_KEY rotates', function (): void {
    $keys = throttleKey();

    config(['app.key' => 'first-application-key']);
    $before = $keys->identifier('person@example.test', null);

    config(['app.key' => 'second-application-key']);

    expect($keys->identifier('person@example.test', null))->not->toBe($before);
});
