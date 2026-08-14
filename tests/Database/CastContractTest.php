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
