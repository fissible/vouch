<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('stores an identifier and round-trips its columns', function (): void {
    $identifier = AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@example.com',
        'is_primary' => true,
    ]);

    $fresh = AuthIdentifier::findOrFail($identifier->id);

    expect($fresh->type)->toBe('email')
        ->and($fresh->value)->toBe('ada@example.com')
        ->and($fresh->is_primary)->toBeTrue()
        ->and($fresh->verified_at)->toBeNull();
});

it('rejects a duplicate identifier of the same type and value', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'ada@example.com']);

    AuthIdentifier::create(['user_id' => 2, 'type' => 'email', 'value' => 'ada@example.com']);
})->throws(\Illuminate\Database\QueryException::class);

it('permits the same value under different identifier types', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'ada']);
    AuthIdentifier::create(['user_id' => 1, 'type' => 'username', 'value' => 'ada']);

    expect(AuthIdentifier::count())->toBe(2);
});

it('encrypts credential secrets at rest', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 1,
        'type' => 'totp',
        'secret' => 'JBSWY3DPEHPK3PXP',
        'strength' => 'possession',
    ]);

    $raw = DB::table('auth_credentials')->where('id', $credential->id)->value('secret');

    expect($raw)->not->toBe('JBSWY3DPEHPK3PXP')
        ->and(AuthCredential::findOrFail($credential->id)->secret)->toBe('JBSWY3DPEHPK3PXP');
});

it('defaults the satisfiability attributes to the safe value', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 1,
        'type' => 'password',
        'secret' => 'hash',
        'strength' => 'knowledge',
    ]);

    $fresh = AuthCredential::findOrFail($credential->id);

    expect($fresh->is_multi_factor)->toBeFalse()
        ->and($fresh->user_verified)->toBeFalse()
        ->and($fresh->phishing_resistant)->toBeFalse()
        ->and($fresh->relying_party_id)->toBeNull()
        ->and($fresh->authenticator_id)->toBeNull()
        ->and($fresh->disabled_at)->toBeNull();
});

it('keeps the secret out of array and JSON serialisation', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 1,
        'type' => 'totp',
        'secret' => 'JBSWY3DPEHPK3PXP',
        'strength' => 'possession',
    ]);

    expect($credential->toArray())->not->toHaveKey('secret')
        ->and($credential->toJson())->not->toContain('JBSWY3DPEHPK3PXP');
});
