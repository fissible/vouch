<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthConnection;
use Fissible\Vouch\Models\AuthFederatedIdentity;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function oidcConnection(string $tenant = 'acme'): AuthConnection
{
    return AuthConnection::create([
        'tenant_id' => $tenant,
        'email_domain' => $tenant . '.example',
        'discovery_url' => 'https://idp.' . $tenant . '.example/.well-known/openid-configuration',
        'client_id' => 'client-' . $tenant,
        'client_secret' => 'secret-' . $tenant,
    ]);
}

it('encrypts the connection client secret at rest', function (): void {
    $conn = oidcConnection();

    $raw = DB::table('auth_connections')->where('id', $conn->id)->value('client_secret');

    expect($raw)->not->toBe('secret-acme')
        ->and(AuthConnection::findOrFail($conn->id)->client_secret)->toBe('secret-acme');
});

it('defaults claim trust and auto-link to the safe value', function (): void {
    $conn = AuthConnection::findOrFail(oidcConnection()->id);

    expect($conn->trust_email_verified)->toBeFalse()
        ->and($conn->auto_link)->toBeFalse();
});

it('enforces uniqueness on connection, issuer and subject', function (): void {
    $conn = oidcConnection();

    AuthFederatedIdentity::create([
        'connection_id' => $conn->id,
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'user_id' => 1,
    ]);

    AuthFederatedIdentity::create([
        'connection_id' => $conn->id,
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'user_id' => 2,
    ]);
})->throws(\Illuminate\Database\QueryException::class);

it('permits the same issuer and subject under a different connection', function (): void {
    $acme = oidcConnection('acme');
    $beta = oidcConnection('beta');

    foreach ([$acme, $beta] as $conn) {
        AuthFederatedIdentity::create([
            'connection_id' => $conn->id,
            'issuer' => 'https://shared-idp.example',
            'subject' => 'sub-1',
            'user_id' => 1,
        ]);
    }

    expect(AuthFederatedIdentity::count())->toBe(2);
});

it('refuses a federated identity with no connection', function (): void {
    AuthFederatedIdentity::create([
        'connection_id' => null,
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'user_id' => 1,
    ]);
})->throws(\Illuminate\Database\QueryException::class);

it('cascades federated identities when their connection is deleted', function (): void {
    // An identity left behind with a dangling connection_id would be an
    // identity with no tenant — exactly what the non-null FK exists to prevent.
    // This also confirms foreign keys are actually enforced in this
    // environment; SQLite silently ignores them unless explicitly enabled.
    $conn = oidcConnection();

    AuthFederatedIdentity::create([
        'connection_id' => $conn->id,
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-1',
        'user_id' => 1,
    ]);

    $conn->delete();

    expect(AuthFederatedIdentity::count())->toBe(0);
});
