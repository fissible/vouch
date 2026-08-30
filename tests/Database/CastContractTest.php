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
    // amr and assurance_proof are read as structures by the evidence adapter.
    // Uncast they arrive as JSON strings and every array read silently fails,
    // which on the proof means authorization sees no evidence at all.
    $id = DB::table('auth_sessions')->insertGetId([
        'session_binding' => str_repeat('a', 64), 'user_id' => 7,
        'amr' => json_encode(['password', 'totp']),
        'assurance_proof' => json_encode(['factors' => [['factor_id' => 'password']]]),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $session = AuthSession::findOrFail($id);

    expect($session->amr)->toBe(['password', 'totp'])
        ->and($session->assurance_proof)->toBe(['factors' => [['factor_id' => 'password']]]);
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

it('hands back a PHP int for an integer column with no cast involved', function (): void {
    /*
     * The premise behind every `integer` cast ruling, pinned so it fails loudly
     * if it ever stops holding.
     *
     * The column-read premise behind the three integer casts -- AuthAttempt.version, AuthChallenge.attempts and
     * AuthCredential.last_used_timestep -- were each recorded as needing MySQL
     * and Postgres to decide, on the stated grounds that those drivers return
     * numeric STRINGS where SQLite returns integers. Measured on PHP 8.4 with
     * pdo_mysql, pdo_pgsql and pdo_sqlite, that is not true: all three hand back
     * a native int, so removing any of those casts changes nothing observable on
     * any supported engine. They are equivalent, not matrix-decidable.
     *
     * That ruling rests entirely on driver behaviour, which is not ours and can
     * change under a PHP or driver upgrade. This asserts it directly, through
     * the query builder so no Eloquent cast can mask the raw value, and it runs
     * on every engine in the matrix. If a driver ever does start stringifying,
     * this fails and the three rulings are back open -- which is the point.
     */
    $id = DB::table('auth_attempts')->insertGetId([
        'handle' => bin2hex(random_bytes(32)),
        'state' => \Fissible\Vouch\Kernel\Attempt\AttemptState::Initiated->value,
        'bound_context' => str_repeat('p', 64),
        'version' => 3,
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    expect(DB::table('auth_attempts')->where('id', $id)->value('version'))->toBeInt();
});

it('reads the attempt version and expiry back as their own types', function (): void {
    /*
     * version drives the compare-and-swap and expires_at bounds the attempt.
     *
     * expires_at is the load-bearing assertion: uncast it arrives as a string and
     * every date comparison against it is lexicographic. `version` is asserted
     * here for the contract's sake, but it does NOT discriminate -- every
     * supported driver returns an int for that column with or without the cast,
     * as the premise test above pins.
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
     * expires_at is provable here; `version` is NOT, on ANY engine.
     *
     * This was previously recorded as cross-engine, on the expectation that
     * MySQL and Postgres return a numeric string for an integer column and would
     * therefore decide it. That was run on both engines rather than assumed, and
     * it does not hold -- the cast's removal leaves the whole Database,
     * Concurrency and Factors suite green on MySQL and Postgres alike. The row
     * is equivalent under the column-read premise pinned above, not matrix-decidable.
     * This premise does not cover aggregates: SUM/NUMERIC expressions are
     * separately normalized and tested by ThrottleReporter.
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
        'weakest_satisfied_at' => now(), 'revoked_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $credentialId = DB::table('auth_credentials')->insertGetId([
        'user_id' => 7, 'type' => 'totp', 'secret' => 'x', 'strength' => 'possession',
        'last_used_at' => now(), 'disabled_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $session = AuthSession::findOrFail($sessionId);
    $credential = AuthCredential::findOrFail($credentialId);

    expect($session->weakest_satisfied_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
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
    $outboxId = DB::table('auth_challenge_outbox')->insertGetId([
        'opaque_id' => bin2hex(random_bytes(32)), 'challenge_id' => $challengeId,
        'payload' => null, 'status' => 'undeliverable',
        'expires_at' => now()->addMinutes(2), 'dispatched_at' => now(),
        'delivered_at' => now(), 'undeliverable_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);
    $assuranceId = DB::table('auth_token_assurances')->insertGetId([
        /*
         * 2.4 Task 2 replaced this table's shape. token_key is a STRING now,
         * deliberately: '42' and '042' are different tokens and an integer
         * column collides them. The old note here warned that a string in the
         * unsignedBigInteger token_id passed on SQLite and failed MySQL strict
         * mode; the hazard has inverted, and a numeric literal is now the wrong
         * type for a column whose identity is byte equality.
         */
        'issuer_key' => 'sanctum', 'token_key' => '90001',
        'subject_key' => 'App\\Models\\User:7', 'tenant_id' => null,
        'actor_kind' => 'human', 'acr' => 'aal1',
        'assurance_proof' => json_encode(['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => []]),
        'weakest_satisfied_at' => now(),
        'created_at' => now(), 'updated_at' => now(),
    ]);

    $outbox = \Fissible\Vouch\Models\AuthChallengeOutbox::findOrFail($outboxId);

    expect(\Fissible\Vouch\Models\AuthIdentifier::findOrFail($identifierId)->verified_at)
        ->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and(\Fissible\Vouch\Models\AuthChallenge::findOrFail($challengeId)->consumed_at)
        ->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($outbox->dispatched_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($outbox->delivered_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        ->and($outbox->undeliverable_at)->toBeInstanceOf(\Illuminate\Support\Carbon::class)
        // issued_at is gone with the replaced shape: recency is authentication
        // time, never issuance time (addendum section 3).
        ->and(\Fissible\Vouch\Models\AuthTokenAssurance::findOrFail($assuranceId)->weakest_satisfied_at)
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
