<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthSession;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * Casts that carry a security meaning, written raw and read back through
 * Eloquent -- the direction that matters, because raw is how the row actually
 * arrives from the database.
 *
 * A dropped cast does not error. It returns the driver's native type: an int on
 * one engine, a numeric string on another. Every `=== true` and every date
 * comparison downstream then quietly changes meaning, and SQLite returning 1
 * where MySQL returns "1" means the same missing cast can pass on one engine and
 * fail on another.
 */

it('reads the assurance attributes back as real booleans', function (): void {
    /*
     * is_multi_factor, user_verified and phishing_resistant decide what a
     * credential may satisfy. Without the boolean cast SQLite hands back int 1
     * and MySQL the string "1", and the strict comparisons that keep an emailed
     * code from claiming AAL3 stop matching -- silently, and differently per
     * engine.
     */
    $id = DB::table('auth_credentials')->insertGetId([
        'user_id' => 7, 'type' => 'totp', 'secret' => 'x', 'strength' => 'possession',
        'is_multi_factor' => 1, 'user_verified' => 1, 'phishing_resistant' => 0,
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $credential = AuthCredential::findOrFail($id);

    expect($credential->is_multi_factor)->toBeTrue()
        ->and($credential->user_verified)->toBeTrue()
        ->and($credential->phishing_resistant)->toBeFalse();
});

it('reads session evidence back as arrays, not raw json', function (): void {
    // amr and assurance_facts are read as structures by the assurance evaluator.
    // Uncast they arrive as JSON strings and every array read silently fails.
    $id = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('a', 64), 'user_id' => 7,
        'amr' => json_encode(['password', 'totp']),
        'assurance_facts' => json_encode(['multi_factor' => true]),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $session = AuthSession::findOrFail($id);

    expect($session->amr)->toBe(['password', 'totp'])
        ->and($session->assurance_facts)->toBe(['multi_factor' => true]);
});

it('reads the grace deadline back as a date, not a string', function (): void {
    /*
     * recovery_grace_expires_at bounds a recovery capability. Uncast it is a
     * string, and a string comparison against a date is a lexicographic
     * comparison -- which happens to work for ISO-8601 in the same format and
     * stops working the moment a driver returns a different one.
     */
    $id = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('b', 64), 'user_id' => 7,
        'amr' => json_encode(['recovery_code']),
        'recovery_grace_expires_at' => now()->addMinutes(15),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(AuthSession::findOrFail($id)->recovery_grace_expires_at)
        ->toBeInstanceOf(\Illuminate\Support\Carbon::class);
});

it('never serializes a stored secret', function (): void {
    /*
     * `$hidden` is a disclosure control, not presentation preference. Eloquent
     * models reach JSON by many routes nobody plans -- an API resource, a queued
     * job payload, a log line, a debug dump -- and toArray() is what every one of
     * them calls.
     *
     * The value is encrypted at rest, so what leaks is ciphertext rather than a
     * plaintext secret. That is still material: it hands an attacker the exact
     * target for an offline attack and confirms the credential exists. This is
     * the same boundary OneTimeSecret defends in memory, defended at the
     * persistence layer.
     */
    $credential = AuthCredential::create([
        'user_id' => 7, 'type' => 'totp', 'secret' => 'seed-material', 'strength' => 'possession',
    ]);

    $reloaded = AuthCredential::findOrFail($credential->id);

    expect(array_keys($reloaded->toArray()))->not->toContain('secret')
        ->and((string) json_encode($reloaded))->not->toContain('seed-material');
});

it('never serializes a connection client secret', function (): void {
    // The same control on the SSO side, where the value is a shared credential
    // with an identity provider rather than a user's own.
    $connection = \Fissible\Vouch\Models\AuthConnection::create([
        'tenant_id' => null,
        'email_domain' => 'acme.example',
        'discovery_url' => 'https://idp.example/.well-known/openid-configuration',
        'client_id' => 'abc',
        'client_secret' => 'super-secret-value',
    ]);

    $reloaded = \Fissible\Vouch\Models\AuthConnection::findOrFail($connection->id);

    expect(array_keys($reloaded->toArray()))->not->toContain('client_secret')
        ->and((string) json_encode($reloaded))->not->toContain('super-secret-value');
});

it('reads the attempt version and expiry back as their own types', function (): void {
    /*
     * version drives the compare-and-swap and expires_at bounds the attempt.
     * Uncast, version arrives as a string on some drivers and the CAS comparison
     * becomes a string comparison; expires_at arrives as a string and every date
     * comparison against it is lexicographic.
     */
    $id = DB::table('auth_attempts')->insertGetId([
        'handle' => bin2hex(random_bytes(32)),
        'state' => \Fissible\Vouch\Kernel\Attempt\AttemptState::Initiated->value,
        'bound_context' => str_repeat('z', 64),
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $attempt = \Fissible\Vouch\Models\AuthAttempt::findOrFail($id);

    /*
     * expires_at is provable here; `version` is NOT. SQLite returns an integer
     * natively, so the cast's removal is invisible on this engine -- probed, and
     * the assertion held without it. It matters on MySQL and Postgres, whose
     * drivers return a numeric string, and where an uncast version turns the
     * compare-and-swap into a string comparison.
     *
     * Recorded as cross-engine rather than dressed up as covered: the row is
     * discharged by the database matrix, not by this test.
     */
    expect($attempt->version)->toBeInt()
        ->and($attempt->expires_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class);
});

/*
 * The remaining SQLite-observable casts, written raw and read back typed.
 *
 * Uncast, a datetime column returns a string and a json column returns a JSON
 * string on EVERY engine including this one -- which is what makes these
 * provable here, unlike the integer casts that SQLite types natively and only
 * the matrix can decide.
 */

it('reads session and credential timestamps back as dates', function (): void {
    /*
     * revoked_at carries the most weight: ValidatesVouchSession and the prune
     * retention window both compare against it, and an uncast string compared to
     * a date is a lexicographic comparison that works by accident of format.
     */
    $sessionId = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('t', 64), 'user_id' => 7, 'amr' => json_encode(['password']),
        'last_factor_at' => now(), 'revoked_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $credentialId = DB::table('auth_credentials')->insertGetId([
        'user_id' => 7, 'type' => 'totp', 'secret' => 'x', 'strength' => 'possession',
        'last_used_at' => now(), 'disabled_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $session = AuthSession::findOrFail($sessionId);
    $credential = AuthCredential::findOrFail($credentialId);

    expect($session->last_factor_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($session->revoked_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($credential->last_used_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($credential->disabled_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class);
});

it('reads identifier, challenge and assurance timestamps back as dates', function (): void {
    $identifierId = DB::table('auth_identifiers')->insertGetId([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example',
        'verified_at' => now(), 'created_at' => now(), 'updated_at' => now(),
    ]);
    $attemptId = DB::table('auth_attempts')->insertGetId([
        'handle' => bin2hex(random_bytes(32)),
        'state' => \Fissible\Vouch\Kernel\Attempt\AttemptState::Initiated->value,
        'bound_context' => str_repeat('u', 64), 'expires_at' => now()->addMinutes(5),
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $challengeId = DB::table('auth_challenges')->insertGetId([
        'attempt_id' => $attemptId, 'factor_type' => 'totp', 'code_hash' => 'd',
        'attempts' => 0, 'expires_at' => now()->addMinutes(5), 'consumed_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $assuranceId = DB::table('auth_token_assurances')->insertGetId([
        'token_id' => 'tok-1', 'amr' => json_encode(['password']),
        'credential_ids' => json_encode([1]), 'acr' => 'aal1',
        'issuing_session_id' => str_repeat('w', 64), 'issued_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(\Fissible\Vouch\Models\AuthIdentifier::findOrFail($identifierId)->verified_at)
        ->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and(\Fissible\Vouch\Models\AuthChallenge::findOrFail($challengeId)->consumed_at)
        ->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and(\Fissible\Vouch\Models\AuthTokenAssurance::findOrFail($assuranceId)->issued_at)
        ->toBeInstanceOf(\Illuminate\Support\Carbon::class);
});

it('reads connection and federated-identity json back as arrays', function (): void {
    $connectionId = DB::table('auth_connections')->insertGetId([
        'tenant_id' => null, 'email_domain' => 'acme.example',
        'discovery_url' => 'https://idp.example/.well-known/openid-configuration',
        'client_id' => 'abc', 'client_secret' => 'enc',
        'claim_mappings' => json_encode(['sub' => 'id']),
        'jit_rules' => json_encode(['create' => true]),
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $federatedId = DB::table('auth_federated_identities')->insertGetId([
        'connection_id' => $connectionId, 'user_id' => 7,
        'subject' => 'sub-1', 'issuer' => 'https://idp.example',
        'claims' => json_encode(['email' => 'ada@acme.example']),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(\Fissible\Vouch\Models\AuthConnection::findOrFail($connectionId)->claim_mappings)
        ->toBe(['sub' => 'id'])
        ->and(\Fissible\Vouch\Models\AuthConnection::findOrFail($connectionId)->jit_rules)
        ->toBe(['create' => true])
        ->and(\Fissible\Vouch\Models\AuthFederatedIdentity::findOrFail($federatedId)->claims)
        ->toBe(['email' => 'ada@acme.example']);
});

it('reads link-request timestamps back as dates', function (): void {
    $connectionId = DB::table('auth_connections')->insertGetId([
        'tenant_id' => null, 'email_domain' => 'b.example',
        'discovery_url' => 'https://b.example/.well-known/openid-configuration',
        'client_id' => 'b', 'client_secret' => 'enc',
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $federatedId = DB::table('auth_federated_identities')->insertGetId([
        'connection_id' => $connectionId, 'user_id' => 7,
        'subject' => 'sub-2', 'issuer' => 'https://b.example',
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $linkId = DB::table('auth_link_requests')->insertGetId([
        'user_id' => 7, 'federated_identity_id' => $federatedId,
        'proven_at' => now(), 'expires_at' => now()->addMinutes(10),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $link = \Fissible\Vouch\Models\AuthLinkRequest::findOrFail($linkId);

    expect($link->proven_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($link->expires_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class);
});
