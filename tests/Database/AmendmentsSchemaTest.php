<?php

declare(strict_types=1);

use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

function verifiedIdentifier(int $userId = 7, string $value = 'ada@acme.example'): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

it('adds every amendment column', function (): void {
    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeTrue()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'is_decoy'))->toBeTrue()
        ->and(Schema::hasTable('auth_challenge_outbox'))->toBeTrue()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeTrue();
});

it('constrains one otp credential per user, type and identifier', function (): void {
    $identifier = verifiedIdentifier();

    $row = [
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ];

    AuthCredential::create($row);
    AuthCredential::create($row);
})->throws(\Illuminate\Database\QueryException::class);

/*
 * Each of the three tests below varies exactly ONE column of the composite key
 * and asserts the pair coexists. Together they pin every column's participation:
 * inserting two identical rows only proves SOME unique index rejects them, so a
 * narrowed index -- unique(['user_id']), say, which would allow a user one
 * credential in total -- would keep the test above green while breaking the
 * package.
 */

it('permits the same user and type against a different identifier', function (): void {
    $shared = ['user_id' => 7, 'type' => 'email_otp', 'strength' => 'possession_weak'];

    AuthCredential::create([...$shared, 'identifier_id' => verifiedIdentifier(7, 'ada@acme.example')->id]);
    AuthCredential::create([...$shared, 'identifier_id' => verifiedIdentifier(7, 'ada+alt@acme.example')->id]);

    expect(AuthCredential::where('user_id', 7)->count())->toBe(2);
});

it('permits the same user and identifier under a different type', function (): void {
    $identifier = verifiedIdentifier();
    $shared = ['user_id' => 7, 'identifier_id' => $identifier->id, 'strength' => 'possession_weak'];

    AuthCredential::create([...$shared, 'type' => 'email_otp']);
    AuthCredential::create([...$shared, 'type' => 'sms_otp']);

    expect(AuthCredential::where('user_id', 7)->count())->toBe(2);
});

it('permits the same type and identifier value under a different user', function (): void {
    // Distinct identifier ROWS, because a credential may only reference its own
    // user's identifier -- GuardsIdentifierLinkage enforces that.
    AuthCredential::create([
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => verifiedIdentifier(7, 'shared@acme.example')->id,
        'strength' => 'possession_weak',
    ]);
    AuthCredential::create([
        'user_id' => 8,
        'type' => 'email_otp',
        'identifier_id' => verifiedIdentifier(8, 'shared@other.example')->id,
        'strength' => 'possession_weak',
    ]);

    expect(AuthCredential::whereIn('user_id', [7, 8])->count())->toBe(2);
});

it('leaves null-identifier credentials unconstrained, which is deliberate here', function (): void {
    /*
     * The inverse of the 2.1 session-binding case, where NULL != NULL broke a
     * constraint by permitting multiple live rows. Here it is exactly right:
     * password, TOTP, recovery and passkey rows carry NULL and are bounded by
     * maxActiveCredentials() instead. This test exists so the next reader does
     * not "fix" it back into the 2.1 mistake.
     */
    $row = ['user_id' => 7, 'type' => 'password', 'identifier_id' => null, 'strength' => 'knowledge'];

    AuthCredential::create($row);
    AuthCredential::create($row);

    expect(AuthCredential::where('user_id', 7)->where('type', 'password')->count())->toBe(2);
});

it('refuses to delete an identifier that a credential references', function (): void {
    $identifier = verifiedIdentifier();

    AuthCredential::create([
        'user_id' => 7,
        'type' => 'email_otp',
        'identifier_id' => $identifier->id,
        'strength' => 'possession_weak',
    ]);

    $identifier->delete();
})->throws(\Illuminate\Database\QueryException::class);

it('stores a timestep as an integer, not a timestamp', function (): void {
    $credential = AuthCredential::create([
        'user_id' => 7,
        'type' => 'totp',
        'strength' => 'possession',
        'last_used_timestep' => 58_400_123,
    ]);

    expect(AuthCredential::findOrFail($credential->id)->last_used_timestep)->toBe(58_400_123);
});

it('permits exactly one enrollment lock row per user and type', function (): void {
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'password']);
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'password']);
})->throws(\Illuminate\Database\QueryException::class);

it('locks one user\'s enrollment types independently of each other', function (): void {
    /*
     * Varies only `type`, which is what makes the test above load-bearing: a
     * narrowed unique(['user_id']) would still reject the identical pair there
     * while serializing a user's password enrollment behind their TOTP
     * enrollment here. Likewise the per-user test below.
     */
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'password']);
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'totp']);

    expect(DB::table('auth_enrollment_locks')->where('user_id', 7)->count())->toBe(2);
});

it('locks each user independently for the same enrollment type', function (): void {
    // A unique(['type']) would serialize every password enrollment in the system.
    DB::table('auth_enrollment_locks')->insert(['user_id' => 7, 'type' => 'password']);
    DB::table('auth_enrollment_locks')->insert(['user_id' => 8, 'type' => 'password']);

    expect(DB::table('auth_enrollment_locks')->where('type', 'password')->count())->toBe(2);
});

it('treats a repeated lock claim as a no-op rather than an error', function (): void {
    // insertOrIgnore is how EnrollmentGuard claims the row. Verified idempotent
    // on SQLite, MySQL and Postgres; upsert() with an empty update array is NOT
    // -- it compiles to a plain INSERT and throws on the second call.
    DB::table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);
    DB::table('auth_enrollment_locks')->insertOrIgnore([['user_id' => 7, 'type' => 'password']]);

    expect(DB::table('auth_enrollment_locks')->count())->toBe(1);
});
