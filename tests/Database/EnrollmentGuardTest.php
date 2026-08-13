<?php

declare(strict_types=1);

use Fissible\Vouch\Enrollment\EnrollmentGuard;
use Fissible\Vouch\Enrollment\EnrollmentRefusalReason;
use Fissible\Vouch\Enrollment\EnrollmentRefused;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

function guard(): EnrollmentGuard
{
    return new EnrollmentGuard(DB::connection(), lockWaitSeconds: 5);
}

function makePassword(): AuthCredential
{
    return AuthCredential::create([
        'user_id' => 7,
        'type' => 'password',
        'secret' => 'digest',
        'strength' => 'knowledge',
    ]);
}

it('permits an enrollment within capacity and returns the write result', function (): void {
    $credential = guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());

    expect($credential)->toBeInstanceOf(AuthCredential::class)
        ->and(AuthCredential::where('user_id', 7)->count())->toBe(1);
});

it('claims the lock row on first use and reuses it afterwards', function (): void {
    guard()->serialize(7, 'password', null, fn (): bool => true);
    guard()->serialize(7, 'password', null, fn (): bool => true);

    expect(DB::table('auth_enrollment_locks')->where('user_id', 7)->count())->toBe(1);
});

it('refuses an enrollment that would exceed capacity, and writes nothing', function (): void {
    makePassword();

    try {
        guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());
        $this->fail('Expected EnrollmentRefused.');
    } catch (EnrollmentRefused $refused) {
        expect($refused->reason)->toBe(EnrollmentRefusalReason::CapacityExceeded);
    }

    expect(AuthCredential::where('user_id', 7)->count())->toBe(1);
});

it('permits replacement, which a pre-check would wrongly refuse', function (): void {
    /*
     * Password change and OTP re-enrollment both disable a row and create one
     * inside the same closure. Counting BEFORE the write would see 1 >= 1 and
     * refuse a legitimate operation; counting after sees the net result. This is
     * why the cardinality check is a post-condition.
     */
    $old = makePassword();

    $new = guard()->serialize(7, 'password', 1, function () use ($old): AuthCredential {
        $old->update(['disabled_at' => now()]);

        return makePassword();
    });

    expect($new->id)->not->toBe($old->id)
        ->and(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(1);
});

it('ignores disabled credentials when counting capacity', function (): void {
    // A revoked TOTP must never block enrolling its replacement. That would be a
    // self-inflicted lockout.
    makePassword()->update(['disabled_at' => now()]);

    guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());

    expect(AuthCredential::where('user_id', 7)->whereNull('disabled_at')->count())->toBe(1);
});

it('skips the capacity check entirely when the driver is unbounded', function (): void {
    foreach (['a', 'b', 'c'] as $suffix) {
        guard()->serialize(7, 'email_otp', null, static function () use ($suffix): void {
            AuthCredential::create([
                'user_id' => 7,
                'type' => 'email_otp',
                'strength' => 'possession_weak',
                'authenticator_id' => $suffix,
            ]);
        });
    }

    // Three live rows for one (user, type). Permitted because identifier_id is
    // null on all three and NULL != NULL in the composite unique index -- the
    // deliberate semantics of Amendment A.
    expect(AuthCredential::where('user_id', 7)->where('type', 'email_otp')->whereNull('disabled_at')->count())
        ->toBe(3);
});

it('rolls the write back when the post-condition refuses', function (): void {
    // The closure creates two credentials where one is allowed. Both must vanish,
    // not just the second: a partially-applied enrollment is worse than none.
    try {
        guard()->serialize(7, 'password', 1, function (): void {
            makePassword();
            makePassword();
        });
        $this->fail('Expected EnrollmentRefused.');
    } catch (EnrollmentRefused) {
        // expected
    }

    expect(AuthCredential::where('user_id', 7)->count())->toBe(0);
});

it('serializes per user and type rather than globally', function (): void {
    // Two users enrolling passwords must not contend with each other, and one
    // user's TOTP enrollment must not contend with their password enrollment.
    guard()->serialize(7, 'password', 1, fn (): AuthCredential => makePassword());
    guard()->serialize(7, 'totp', 1, fn (): AuthCredential => AuthCredential::create([
        'user_id' => 7, 'type' => 'totp', 'secret' => 'JBSWY3DPEHPK3PXP', 'strength' => 'possession',
    ]));

    expect(DB::table('auth_enrollment_locks')->count())->toBe(2);
});
