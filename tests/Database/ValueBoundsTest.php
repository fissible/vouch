<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthConnection;
use Fissible\Vouch\Models\AuthFederatedIdentity;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Persistence\ValueBoundViolation;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function boundedConnection(): AuthConnection
{
    return AuthConnection::create(['tenant_id' => 'acme', 'email_domain' => 'acme.example']);
}

/*
 * These assertions only mean anything because the check lives in PHP.
 *
 * SQLite does not enforce VARCHAR length at all — an over-length value is
 * stored in full. MySQL rejects under a strict sql_mode and SILENTLY TRUNCATES
 * without one. Postgres rejects. Relying on the column definition alone would
 * make every test here vacuous on the suite's own default engine, and would
 * leave a non-strict MySQL host able to truncate two distinct issuers into a
 * collision under the unique (connection_id, issuer, subject) index.
 */

it('refuses an over-length federated identity subject', function (): void {
    AuthFederatedIdentity::create([
        'connection_id' => boundedConnection()->id,
        'issuer' => 'https://idp.acme.example',
        'subject' => str_repeat('s', 256),
    ]);
})->throws(ValueBoundViolation::class);

it('refuses a non-ASCII subject even within the length bound', function (): void {
    // OIDC Core §2 specifies ASCII. A broken or hostile IdP is an input
    // boundary, not a trusted peer.
    AuthFederatedIdentity::create([
        'connection_id' => boundedConnection()->id,
        'issuer' => 'https://idp.acme.example',
        'subject' => 'sub-café',
    ]);
})->throws(ValueBoundViolation::class);

it('refuses an over-length issuer', function (): void {
    AuthFederatedIdentity::create([
        'connection_id' => boundedConnection()->id,
        'issuer' => 'https://idp.acme.example/' . str_repeat('x', 256),
        'subject' => 'sub-1',
    ]);
})->throws(ValueBoundViolation::class);

it('refuses a non-ASCII issuer', function (): void {
    AuthFederatedIdentity::create([
        'connection_id' => boundedConnection()->id,
        'issuer' => 'https://idp.acmé.example',
        'subject' => 'sub-1',
    ]);
})->throws(ValueBoundViolation::class);

it('accepts a subject and issuer exactly at the bound', function (): void {
    $identity = AuthFederatedIdentity::create([
        'connection_id' => boundedConnection()->id,
        'issuer' => 'https://' . str_repeat('i', 255 - 8),
        'subject' => str_repeat('s', 255),
    ]);

    expect(mb_strlen($identity->subject))->toBe(255)
        ->and(mb_strlen($identity->issuer))->toBe(255);
});

it('refuses an over-length tenant id on a connection', function (): void {
    AuthConnection::create(['tenant_id' => str_repeat('t', 256)]);
})->throws(ValueBoundViolation::class);

it('refuses an over-length tenant id on a policy', function (): void {
    AuthPolicy::create([
        'tenant_id' => str_repeat('t', 256),
        'scope' => 'login',
        'document' => ['all_of' => ['password']],
    ]);
})->throws(ValueBoundViolation::class);

it('refuses an over-length tenant id on an attempt', function (): void {
    AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::Initiated,
        'version' => 1,
        'tenant_id' => str_repeat('t', 256),
        'expires_at' => now()->addMinutes(10),
    ]);
})->throws(ValueBoundViolation::class);

it('refuses an over-length identifier value', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => str_repeat('v', 256)]);
})->throws(ValueBoundViolation::class);

it('enforces the bound on update, not only on insert', function (): void {
    $connection = boundedConnection();

    $connection->update(['tenant_id' => str_repeat('t', 256)]);
})->throws(ValueBoundViolation::class);

it('leaves nothing persisted when a write is refused', function (): void {
    try {
        AuthConnection::create(['tenant_id' => str_repeat('t', 256)]);
    } catch (ValueBoundViolation) {
        // expected
    }

    expect(DB::table('auth_connections')->count())->toBe(0);
});

it('permits a null tenant id, which is the single-tenant default', function (): void {
    $connection = AuthConnection::create(['tenant_id' => null, 'email_domain' => 'acme.example']);

    expect($connection->tenant_id)->toBeNull();
});
