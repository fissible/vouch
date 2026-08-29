<?php

declare(strict_types=1);

use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;

/*
 * 2.4 Task 1 — the value objects.
 *
 * These exist because a bare integer id is ambiguous the moment more than one
 * guard, model or issuer exists. The addendum's §6 requires ONE type used
 * identically when a token is resolved and when its evidence is persisted; two
 * representations that drift are how an assurance record for one token comes to
 * validate another.
 */

it('renders a subject key canonically', function (): void {
    expect(SubjectKey::of('App\\Models\\User', 7)->toString())->toBe('App\\Models\\User:7');
});

it('treats the canonical rendering as the identity', function (): void {
    expect(SubjectKey::of('App\\Models\\User', 7)->equals(SubjectKey::of('App\\Models\\User', 7)))->toBeTrue();
});

it('does not conflate the same id under different providers', function (): void {
    // The entire reason the provider is part of the key.
    expect(SubjectKey::of('App\\Models\\User', 7)->equals(SubjectKey::of('App\\Models\\Service', 7)))->toBeFalse();
});

it('compares ids by value, never by numeric coercion', function (): void {
    /*
     * '07' and 7 are the same number and different identities. A key that
     * coerced would let one subject's evidence answer for another's.
     */
    expect(SubjectKey::of('App\\Models\\User', '07')->equals(SubjectKey::of('App\\Models\\User', 7)))->toBeFalse();
});

it('accepts a string id, because not every host keys users by integer', function (): void {
    expect(SubjectKey::of('App\\Models\\User', '01J0X')->toString())->toBe('App\\Models\\User:01J0X');
});

it('refuses an empty provider or id rather than rendering a half key', function (mixed $provider, mixed $id): void {
    expect(fn () => SubjectKey::of($provider, $id))->toThrow(InvalidArgumentException::class);
})->with([
    'empty provider' => ['', 7],
    'empty id' => ['App\\Models\\User', ''],
]);

it('round-trips through its canonical rendering', function (): void {
    // Persisted as one string column; read back as the same value.
    $key = SubjectKey::of('App\\Models\\User', 7);

    expect(SubjectKey::fromString($key->toString())->equals($key))->toBeTrue();
});

it('keeps a provider containing a colon unambiguous', function (): void {
    /*
     * The rendering is provider:id and the id is whatever follows the LAST
     * colon, so a provider may contain colons and still round-trip.
     */
    $key = SubjectKey::of('tenant:acme\\User', 7);

    expect(SubjectKey::fromString($key->toString())->equals($key))->toBeTrue();
});

it('refuses a colon in the id, which is what makes the rendering decidable', function (): void {
    /*
     * Without this rule `a:b:c` could mean ('a:b', 'c') or ('a', 'b:c'), and
     * two readings of one string is two identities. The last-colon rule above
     * only decides the parse if ids cannot contain colons, so the constructor
     * enforces it rather than the parser guessing.
     */
    expect(fn () => SubjectKey::of('App\\Models\\User', 'a:b'))
        ->toThrow(InvalidArgumentException::class);
});

it('refuses a malformed rendering rather than inventing a half key', function (string $malformed): void {
    expect(fn () => SubjectKey::fromString($malformed))->toThrow(InvalidArgumentException::class);
})->with([
    'no separator' => ['AppModelsUser7'],
    'empty id' => ['App\\Models\\User:'],
    'empty provider' => [':7'],
    'empty string' => [''],
]);

/*
 * ResolvedToken — what a driver returns when it claims a request.
 */

it('carries the issuer, token, subject and usability of a claimed request', function (): void {
    $subject = SubjectKey::of('App\\Models\\User', 7);
    $resolved = new ResolvedToken('sanctum', '42', $subject, usable: true);

    expect($resolved->issuerKey)->toBe('sanctum')
        ->and($resolved->tokenKey)->toBe('42')
        ->and($resolved->subject->equals($subject))->toBeTrue()
        ->and($resolved->usable)->toBeTrue();
});

it('can report a token it recognised but which is not usable', function (): void {
    /*
     * Expiry, deletion and revocation are the driver's business, not the
     * caller's. "Recognised" must not imply "usable" — the addendum makes
     * usability part of the resolved value precisely so a row lookup cannot be
     * mistaken for a validity check.
     */
    $resolved = new ResolvedToken('sanctum', '42', SubjectKey::of('App\\Models\\User', 7), usable: false);

    expect($resolved->usable)->toBeFalse();
});

/*
 * TokenGrant — what the HOST authorized. Vouch evaluates assurance; it never
 * decides abilities. That line is the same one drawn in Task 6.
 */

it('carries host-authorized abilities without interpreting them', function (): void {
    $grant = new TokenGrant(
        subject: SubjectKey::of('App\\Models\\User', 7),
        name: 'ci-deploy',
        abilities: ['deploy:write', 'logs:read'],
        actor: ActorKind::Human,
    );

    expect($grant->abilities)->toBe(['deploy:write', 'logs:read']);
});

it('carries the tenant, because assurance is tenant-scoped', function (): void {
    /*
     * Addendum §6: evidence minted under one tenant's policy must not authorize
     * under another's. Tenant has to travel with the grant or it cannot reach
     * the evidence record in Task 2.
     */
    $grant = new TokenGrant(
        subject: SubjectKey::of('App\\Models\\User', 7),
        name: 'ci',
        abilities: [],
        tenantId: 'acme',
    );

    expect($grant->tenantId)->toBe('acme');
});

it('treats a null tenant as global rather than as unset', function (): void {
    $grant = new TokenGrant(
        subject: SubjectKey::of('App\\Models\\User', 7),
        name: 'ci',
        abilities: [],
    );

    expect($grant->tenantId)->toBeNull();
});

it('defaults an actor to human, so machine access is never implicit', function (): void {
    $grant = new TokenGrant(
        subject: SubjectKey::of('App\\Models\\User', 7),
        name: 'default',
        abilities: [],
    );

    expect($grant->actor)->toBe(ActorKind::Human);
});

it('distinguishes a machine grant, which is an actor class and not an assurance level', function (): void {
    $grant = new TokenGrant(
        subject: SubjectKey::of('App\\Models\\Service', 3),
        name: 'exporter',
        abilities: ['export:read'],
        actor: ActorKind::Machine,
    );

    expect($grant->actor)->toBe(ActorKind::Machine);
});

/*
 * IssuedToken — plaintext exists once, at issuance.
 */

it('exposes the plaintext at issuance', function (): void {
    $issued = new IssuedToken('sanctum', '42', SubjectKey::of('App\\Models\\User', 7), 'plain-text-value');

    expect($issued->plainText)->toBe('plain-text-value')
        ->and($issued->tokenKey)->toBe('42');
});

it('redacts the plaintext from the renderers it can actually control', function (): void {
    /*
     * A token reaching a log line, an exception trace or a queued payload is a
     * credential somewhere nobody audits.
     *
     * The scope is deliberately narrow: json_encode() and var_dump()/dd() route
     * through JsonSerializable and __debugInfo, which the object owns. It does
     * NOT claim var_export() or serialize() safety — those read declared
     * properties directly, so promising it here would force a contorted API to
     * satisfy a test rather than a real threat. Task 3 owns not putting an
     * IssuedToken into a queue payload in the first place.
     */
    $issued = new IssuedToken('sanctum', '42', SubjectKey::of('App\\Models\\User', 7), 'plain-text-value');

    expect(json_encode($issued))->not->toContain('plain-text-value')
        ->and(print_r($issued->__debugInfo(), true))->not->toContain('plain-text-value');
});

it('still hands the plaintext to a caller that asks for it directly', function (): void {
    // The pair for the redaction test: an object that hid the secret from its
    // own accessor would pass the test above and be useless.
    $issued = new IssuedToken('sanctum', '42', SubjectKey::of('App\\Models\\User', 7), 'plain-text-value');

    expect($issued->plainText)->toBe('plain-text-value');
});
