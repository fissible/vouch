<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthFederatedIdentity;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\ValueBoundViolation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * The bounds loop itself, rather than any single bound. Both survivors here are
 * about which attributes get checked at all.
 */

it('keeps checking later attributes after skipping a non-string one', function (): void {
    /*
     * `continue`, not `break`. valueBounds() is iterated in declaration order,
     * and a null attribute is skipped as not-a-string. With `break` the loop
     * abandons every LATER bound -- so one unset attribute silently disables the
     * validation of all the ones declared after it.
     *
     * subject is declared first and left null here; issuer is declared second and
     * violates. Only the surviving loop catches it.
     */
    expect(fn (): bool => (new AuthFederatedIdentity([
        'user_id' => 7,
        'connection_id' => 1,
        'subject' => null,
        'issuer' => str_repeat('i', 300),
    ]))->save())->toThrow(ValueBoundViolation::class);
});

it('applies the ascii rule only where it is declared', function (): void {
    /*
     * `($rule['ascii'] ?? false)`. Read as `?? true`, every bounded attribute
     * becomes ASCII-only -- and AuthIdentifier.value is an email address, which
     * may legitimately carry non-ASCII. That would refuse valid registrations
     * with a message about a rule nobody wrote.
     */
    $identifier = new AuthIdentifier([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'adá@acme.example',
    ]);

    expect($identifier->save())->toBeTrue()
        ->and(AuthIdentifier::query()->count())->toBe(1);
});

it('still refuses non-ascii where the rule IS declared', function (): void {
    // The other side: subject carries ascii => true, so the rule must fire there.
    expect(fn (): bool => (new AuthFederatedIdentity([
        'user_id' => 7,
        'connection_id' => 1,
        'subject' => 'subjéct',
        'issuer' => 'https://idp.example',
    ]))->save())->toThrow(ValueBoundViolation::class);
});
