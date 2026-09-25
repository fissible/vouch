<?php

declare(strict_types=1);

use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Fissible\Vouch\Throttle\IpCanonicalizer;
use Fissible\Vouch\Throttle\ThrottleDimension;
use Fissible\Vouch\Throttle\ThrottleKey;
use Fissible\Vouch\Throttle\ThrottleSubject;

function throttleKey(): ThrottleKey
{
    return new ThrottleKey(new IdentifierCanonicalizer(), new IpCanonicalizer());
}

function throttleDigest(ThrottleSubject $subject): string
{
    return $subject->digest;
}

function nullableThrottleDigest(?ThrottleSubject $subject): ?string
{
    return $subject?->digest;
}

it('canonicalizes identifier case and Unicode composition before derivation', function (): void {
    $keys = throttleKey();

    expect(throttleDigest($keys->identifier("\u{00C9}lodie@example.test", null)))
        ->toBe(throttleDigest($keys->identifier("E\u{0301}LODIE@example.test", null)))
        // Lowercasing J + caron creates a decomposed form that must be
        // normalized again; constructor-time normalization alone cannot pass.
        ->and(throttleDigest($keys->identifier("\u{01F0}@example.test", null)))
        ->toBe(throttleDigest($keys->identifier("J\u{030C}@example.test", null)));
});

it('does not apply provider-specific identifier aliases', function (): void {
    $keys = throttleKey();

    expect(throttleDigest($keys->identifier('user.name@gmail.com', null)))
        ->not->toBe(throttleDigest($keys->identifier('username@gmail.com', null)));
});

it('distinguishes an absent tenant from an empty tenant', function (): void {
    $keys = throttleKey();

    expect(throttleDigest($keys->identifier('person@example.test', null)))
        ->not->toBe(throttleDigest($keys->identifier('person@example.test', '')));
});

it('keeps each present tenant in a distinct throttle subject', function (): void {
    $keys = throttleKey();

    expect(throttleDigest($keys->identifier('person@example.test', 'tenant-a')))
        ->not->toBe(throttleDigest($keys->identifier('person@example.test', 'tenant-b')));
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

    $identifier = throttleDigest($keys->identifier('person@example.test', 'tenant-a'));

    expect($identifier)
        ->not->toBe(throttleDigest($keys->recovery('person@example.test', 'tenant-a')));
    expect($identifier)
        ->not->toBe(throttleDigest($keys->issuance('person@example.test', 'tenant-a')));
    expect($identifier)
        ->not->toBe(throttleDigest($keys->ceremony('person@example.test', 'tenant-a')));
});

it('canonicalizes IPv4 and separates distinct addresses', function (): void {
    $keys = throttleKey();
    $canonical = nullableThrottleDigest($keys->ip('192.0.2.10', null));
    $roundTrip = nullableThrottleDigest($keys->ip((string) inet_ntop((string) inet_pton('192.0.2.10')), null));
    $other = nullableThrottleDigest($keys->ip('192.0.2.11', null));

    expect([$canonical, $roundTrip, $other])->each->toBeString()
        ->and($canonical)->toBe($roundTrip)
        ->and($canonical === $other)->toBeFalse();
});

it('treats an IPv4-mapped IPv6 address as its IPv4 subject', function (): void {
    $keys = throttleKey();

    expect(nullableThrottleDigest($keys->ip('::ffff:192.0.2.10', null)))
        ->toBe(nullableThrottleDigest($keys->ip('192.0.2.10', null)));
});

it('buckets equivalent IPv6 text and privacy addresses by 64-bit prefix', function (): void {
    $keys = throttleKey();

    $compressed = nullableThrottleDigest($keys->ip('2001:db8:abcd:1234::1', null));
    $expanded = nullableThrottleDigest($keys->ip('2001:0db8:abcd:1234:0000:0000:0000:0001', null));
    $privacy = nullableThrottleDigest($keys->ip('2001:db8:abcd:1234:deaf:beef:cafe:babe', null));
    $neighbor = nullableThrottleDigest($keys->ip('2001:db8:abcd:1235::1', null));

    expect([$compressed, $expanded, $privacy, $neighbor])->each->toBeString()
        ->and($compressed)->toBe($expanded)->toBe($privacy)
        ->and($compressed === $neighbor)->toBeFalse();
});

it('uses canonical IP and identifier segments for tuple markers', function (): void {
    $keys = throttleKey();

    $canonical = nullableThrottleDigest($keys->ipIdentifier(
        '2001:db8:abcd:1234::1',
        "\u{00C9}lodie@example.test",
        null,
    ));

    expect($canonical)->toBe(nullableThrottleDigest($keys->ipIdentifier(
        '2001:db8:abcd:1234:ffff:ffff:ffff:ffff',
        "E\u{0301}LODIE@example.test",
        null,
    )))
        ->and($canonical === nullableThrottleDigest($keys->ipIdentifier(
            '2001:db8:abcd:1234::1',
            'other@example.test',
            null,
        )))->toBeFalse()
        ->and($canonical === nullableThrottleDigest($keys->ipIdentifier(
            '2001:db8:abcd:1235::1',
            "\u{00C9}lodie@example.test",
            null,
        )))->toBeFalse();
});

it('skips the IP dimensions when client IP is absent', function (): void {
    $keys = throttleKey();

    expect($keys->ip(null, null))->toBeNull()
        ->and($keys->ipIdentifier(null, 'person@example.test', null))->toBeNull();
});

it('rejects invalid client IP instead of sharing an unknown bucket', function (): void {
    expect(fn (): ?ThrottleSubject => throttleKey()->ip('not-an-ip', null))
        ->toThrow(InvalidArgumentException::class, 'not a valid IP address');
});

it('carries the derivation domain as a typed persistence dimension', function (): void {
    $keys = throttleKey();

    expect($keys->identifier('person@example.test', null)->dimension)
        ->toBe(ThrottleDimension::Identifier)
        ->and($keys->recovery('person@example.test', null)->dimension)
        ->toBe(ThrottleDimension::Recovery)
        ->and($keys->issuance('person@example.test', null)->dimension)
        ->toBe(ThrottleDimension::Issuance)
        ->and($keys->ip('192.0.2.10', null)?->dimension)
        ->toBe(ThrottleDimension::IpV4)
        ->and($keys->ip('2001:db8::1', null)?->dimension)
        ->toBe(ThrottleDimension::IpV6)
        ->and($keys->ipIdentifier('192.0.2.10', 'person@example.test', null)?->dimension)
        ->toBe(ThrottleDimension::IpIdentifier)
        ->and($keys->tenant(null)->dimension)
        ->toBe(ThrottleDimension::Tenant)
        ->and($keys->global()->dimension)
        ->toBe(ThrottleDimension::Global);
});

it('pins the HMAC domain and tenant framing used by persisted throttle keys', function (): void {
    $keys = throttleKey();

    expect(throttleDigest($keys->identifier('person@example.test', 'tenant-a')))
        ->toBe(SessionBinding::forSegments(
            BindingDomain::ThrottleIdentifier,
            'tenant.present',
            'tenant-a',
            'person@example.test',
        ))
        ->and(nullableThrottleDigest($keys->ip('192.0.2.10', null)))
        ->toBe(SessionBinding::forSegments(
            BindingDomain::ThrottleIpV4,
            'tenant.absent',
            '192.0.2.10',
        ))
        ->and(nullableThrottleDigest($keys->ip('2001:db8:abcd:1234::1', null)))
        ->toBe(SessionBinding::forSegments(
            BindingDomain::ThrottleIpV6,
            'tenant.absent',
            '2001:db8:abcd:1234::',
        ));
});

it('derives all non-IP throttle dimensions without exposing their subjects', function (): void {
    $keys = throttleKey();
    $raw = 'raw-person@example.test';
    $derived = [
        throttleDigest($keys->identifier($raw, null)),
        throttleDigest($keys->recovery($raw, null)),
        throttleDigest($keys->issuance($raw, null)),
        throttleDigest($keys->tenant(null)),
        throttleDigest($keys->tenant('tenant-a')),
        throttleDigest($keys->global()),
    ];
    $ip = nullableThrottleDigest($keys->ip('192.0.2.10', null));
    $tuple = nullableThrottleDigest($keys->ipIdentifier('192.0.2.10', $raw, null));

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
    $before = throttleDigest($keys->identifier('person@example.test', null));

    config(['app.key' => 'second-application-key']);

    expect(throttleDigest($keys->identifier('person@example.test', null)))->not->toBe($before);
});

it('refuses to construct a persistence subject from a raw or malformed value', function (
    string $value,
): void {
    expect(fn (): ThrottleSubject => new ThrottleSubject(ThrottleDimension::Identifier, $value))
        ->toThrow(InvalidArgumentException::class, 'lowercase HMAC-SHA256 digest');
})->with([
    'raw identifier' => ['person@example.test'],
    'uppercase digest' => [str_repeat('A', 64)],
    'short digest' => [str_repeat('a', 63)],
    'long digest' => [str_repeat('a', 65)],
]);

/*
 * #48. Verification redemption is its own authority.
 *
 * redeem() used ThrottleKey::recovery(), so guessing a verification code backed
 * off password recovery for the same address.
 *
 * Counter rows are unique on (dimension, subject_digest), so a distinct
 * dimension alone already separates them -- an earlier note here claimed that
 * reusing EITHER the dimension or the binding domain necessarily shares a row,
 * which is not how that uniqueness works. Both are kept distinct anyway, as an
 * adopted contract rather than a consequence: a shared binding domain makes one
 * identifier's two ceremony digests equal, leaving the partition resting on the
 * dimension column alone and any operation that widened its guard able to cross
 * it.
 *
 * Issuance stays shared, by decision -- both ceremonies spend the same outbound
 * delivery budget for one address. That is asserted where it is observable, in
 * the accounting suite; here it is only the reason ceremony() is untouched.
 */

it('separates verification redemption from recovery for the same subject', function (): void {
    $keys = throttleKey();
    $verification = throttleDigest($keys->verification('person@example.test', 'tenant-a'));

    /*
     * A different digest, not merely a different label. An accessor that
     * delegated to recovery() produces the same digest here, and one that
     * changed the dimension while keeping recovery's binding domain produces the
     * same digest too -- leaving the partition resting on the dimension column
     * alone. Counter rows are unique on (dimension, subject_digest), so equal
     * digests under DIFFERENT dimensions do not share a row; what they lose is
     * the second, independent separation this contract asks for.
     */
    expect($verification)
        ->not->toBe(throttleDigest($keys->recovery('person@example.test', 'tenant-a')))
        ->and($verification)
        ->not->toBe(throttleDigest($keys->ceremony('person@example.test', 'tenant-a')))
        ->and($verification)
        ->not->toBe(throttleDigest($keys->identifier('person@example.test', 'tenant-a')));
});

it('separates distinct verification identifiers from each other', function (): void {
    $keys = throttleKey();

    /*
     * The obvious thing nothing else asserted. A derivation that kept the
     * tenant scope and the new dimension and domain, but replaced the identifier
     * segment with a CONSTANT, passed every other test here -- and would back
     * off every address in a tenant as soon as one of them was guessed at.
     */
    expect(throttleDigest($keys->verification('ada@example.test', 'tenant-a')))
        ->not->toBe(throttleDigest($keys->verification('neighbour@example.test', 'tenant-a')))
        ->and(throttleDigest($keys->verification('ada@example.test', null)))
        ->not->toBe(throttleDigest($keys->verification('neighbour@example.test', null)));
});

it('gives verification redemption its own dimension', function (): void {
    $keys = throttleKey();

    expect($keys->verification('person@example.test', null)->dimension)
        ->not->toBe(ThrottleDimension::Recovery)
        ->and($keys->verification('person@example.test', null)->dimension)
        ->not->toBe(ThrottleDimension::Ceremony);
});

it('canonicalizes and scopes verification subjects like every other dimension', function (): void {
    $keys = throttleKey();

    /*
     * The same treatment as its neighbours, or the partition introduces a gap of
     * its own: an uncanonicalized subject gives one address several buckets, and
     * an unscoped one merges tenants.
     */
    expect(throttleDigest($keys->verification('Person@Example.Test', null)))
        ->toBe(throttleDigest($keys->verification('person@example.test', null)))
        /*
         * Unicode composition too, not only ASCII case. A lowercasing that
         * handled ASCII alone gave one address two buckets for a composed and a
         * decomposed spelling, and passed a case-only assertion.
         */
        ->and(throttleDigest($keys->verification("jos\u{e9}@example.test", null)))
        ->toBe(throttleDigest($keys->verification("jose\u{301}@example.test", null)))
        /*
         * Non-ASCII CASE, separately from composition. The pair above is already
         * lowercase, so NFC normalization plus strtolower() satisfied it while
         * leaving accented capitals in their own bucket -- one address, two
         * budgets, which is the gap canonicalization exists to close.
         */
        ->and(throttleDigest($keys->verification("\u{c9}lodie@example.test", null)))
        ->toBe(throttleDigest($keys->verification("\u{e9}lodie@example.test", null)))
        ->and(throttleDigest($keys->verification('person@example.test', 'tenant-a')))
        ->not->toBe(throttleDigest($keys->verification('person@example.test', 'tenant-b')))
        ->and(throttleDigest($keys->verification('person@example.test', null)))
        ->not->toBe(throttleDigest($keys->verification('person@example.test', 'tenant-a')))
        /*
         * An absent tenant is not an empty one. Treating them alike merges a
         * single-tenant host's traffic with an explicitly-empty scope, and this
         * suite already pins that distinction for the other dimensions.
         */
        ->and(throttleDigest($keys->verification('person@example.test', null)))
        ->not->toBe(throttleDigest($keys->verification('person@example.test', '')));
});
