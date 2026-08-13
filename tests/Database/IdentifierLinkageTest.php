<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Persistence\IdentifierLinkageViolation;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

function identifierFor(int $userId, string $value, bool $verified = true): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => $verified ? now() : null,
    ]);
}

function otpCredential(int $userId, AuthIdentifier $identifier): AuthCredential
{
    return AuthCredential::create([
        'user_id' => $userId,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ]);
}

it('links a credential to a verified identifier owned by the same user', function (): void {
    $identifier = identifierFor(7, 'ada@acme.example');

    expect(otpCredential(7, $identifier)->identifier_id)->toBe($identifier->id);
});

it('refuses to link a credential to another user identifier', function (): void {
    // Two independent foreign keys cannot relate user_id to the identifier's
    // owner. Without this check, an OTP credential on user 7 could deliver codes
    // to user 8's verified address.
    otpCredential(7, identifierFor(8, 'grace@acme.example'));
})->throws(IdentifierLinkageViolation::class);

it('refuses to link a credential to an unverified identifier', function (): void {
    // An unverified identifier is attacker-supplied until proven. Linking OTP
    // delivery to one routes codes to an address nobody has demonstrated control of.
    otpCredential(7, identifierFor(7, 'unproven@acme.example', verified: false));
})->throws(IdentifierLinkageViolation::class);

it('refuses to link a credential to an identifier that does not exist', function (): void {
    AuthCredential::create([
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => 999_999,
        'strength' => 'possession_weak',
    ]);
})->throws(IdentifierLinkageViolation::class);

it('permits a credential with no identifier at all', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 7,
        'type' => 'password',
        'secret' => 'digest',
        'strength' => 'knowledge',
    ]);

    expect($credential->identifier_id)->toBeNull();
});

it('freezes an identifier value once a credential references it', function (): void {
    /*
     * The account-takeover path this closes: mutating the address in place
     * silently redirects every existing OTP credential pointing at that row, so
     * an attacker who can edit a profile field receives all future codes without
     * touching a single credential.
     */
    $identifier = identifierFor(7, 'ada@acme.example');
    otpCredential(7, $identifier);

    $identifier->update(['value' => 'attacker@evil.example']);
})->throws(IdentifierLinkageViolation::class);

it('still permits editing an identifier no credential references', function (): void {
    $identifier = identifierFor(7, 'typo@acme.example');

    $identifier->update(['value' => 'fixed@acme.example']);

    expect(AuthIdentifier::findOrFail($identifier->id)->value)->toBe('fixed@acme.example');
});

it('still permits editing other columns of a referenced identifier', function (): void {
    // Only `value` is frozen. Freezing the whole row would block re-verification
    // and primary-address changes, neither of which redirects delivery.
    $identifier = identifierFor(7, 'ada@acme.example');
    otpCredential(7, $identifier);

    $identifier->update(['is_primary' => true]);

    expect(AuthIdentifier::findOrFail($identifier->id)->is_primary)->toBeTrue();
});

it('freezes the value even when the referencing credential is disabled', function (): void {
    // restrictOnDelete blocks deletion regardless of disabled_at, and the same
    // logic applies to mutation: a disabled credential can be re-enabled, so its
    // delivery target must not have moved underneath it in the meantime.
    $identifier = identifierFor(7, 'ada@acme.example');
    $credential = otpCredential(7, $identifier);
    $credential->update(['disabled_at' => now()]);

    $identifier->update(['value' => 'attacker@evil.example']);
})->throws(IdentifierLinkageViolation::class);
