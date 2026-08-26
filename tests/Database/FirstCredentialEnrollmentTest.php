<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Enrollment\FirstCredentialEnrollment;
use Fissible\Vouch\Enrollment\FirstCredentialRequest;
use Fissible\Vouch\Enrollment\FirstCredentialResult;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);



/*
 * 2.3d Task 3. Attaches a first identifier and credential to a user the host
 * already created, then triggers Task 1's verification ceremony.
 *
 * The two properties that carry the tests are the neutral result contract --
 * the host must be able to build an enumeration-safe registration endpoint on
 * top of this, which a result distinguishing "created" from "already existed"
 * would foreclose -- and the concurrency semantics, which must go through
 * EnrollmentGuard rather than a bare insert.
 */

function firstCredentialRequest(
    int $userId = 1,
    string $value = 'ada@acme.example',
    string $password = 'first-password',
): FirstCredentialRequest {
    return new FirstCredentialRequest(
        userId: $userId,
        identifierType: 'email',
        identifierValue: $value,
        password: $password,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

/** Enroll with delivery bound so the triggered ceremony can be observed. */
/** @return array{0: FirstCredentialResult, 1: ArrayOtpDelivery} */
function enrollFirstCredential(?FirstCredentialRequest $request = null): array
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    $result = app(FirstCredentialEnrollment::class)->enroll($request ?? firstCredentialRequest());

    foreach (DB::table('auth_identifier_verification_outbox')->pluck('opaque_id') as $opaqueId) {
        app(VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return [$result, $delivery];
}

it('attaches an identifier and credential, leaving the identifier unverified', function (): void {
    [$result, ] = enrollFirstCredential();

    $identifier = AuthIdentifier::query()->where('value', 'ada@acme.example')->first();

    /*
     * The first identifier starts unverified by design. Marking it verified
     * because the host asserted it would defeat the whole point of Task 1's
     * ceremony -- control has not been proven yet.
     */
    expect($result)->toBe(FirstCredentialResult::Accepted)
        ->and($identifier?->verified_at)->toBeNull()
        ->and($identifier?->user_id)->toBe(1)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'password')->count())->toBe(1)
        ->and(Hash::check('first-password', stringValue(AuthCredential::query()
            ->where('user_id', 1)->value('secret'))))->toBeTrue();
});

it('triggers the verification ceremony for the new identifier', function (): void {
    [, $delivery] = enrollFirstCredential();

    /*
     * Task 1 established that an unverified identifier is invisible to login.
     * Enrollment that did not start the ceremony would leave every new account
     * silently unable to sign in, which is the install cliff Task 1 removed.
     */
    expect($delivery->sent)->toHaveCount(1)
        ->and($delivery->lastIdentifier()->value)->toBe('ada@acme.example');
});

it('returns the same result whether or not the identifier already existed', function (): void {
    AuthIdentifier::create([
        'user_id' => 99,
        'type' => 'email',
        'value' => 'taken@acme.example',
        'verified_at' => now(),
    ]);

    $observe = function (FirstCredentialRequest $request): array {
        $before = [
            'ceremony' => (int) DB::table('auth_throttle_counters')->where('dimension', 'ceremony')->sum('count'),
            'outbox' => DB::table('auth_identifier_verification_outbox')->count(),
        ];

        /*
         * Measured BEFORE the worker runs. A decoy row is deleted on delivery
         * while a real one stays recorded, so draining first would make the
         * deltas differ for a reason that has nothing to do with neutrality.
         */
        app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
        $result = app(FirstCredentialEnrollment::class)->enroll($request);

        return [
            'result' => $result,
            'ceremony' => (int) DB::table('auth_throttle_counters')->where('dimension', 'ceremony')->sum('count') - $before['ceremony'],
            'outbox' => DB::table('auth_identifier_verification_outbox')->count() - $before['outbox'],
        ];
    };

    $fresh = $observe(firstCredentialRequest(1, 'ada@acme.example'));
    $taken = $observe(firstCredentialRequest(2, 'taken@acme.example'));

    /*
     * Returning the same enum is not enough. A host builds its registration
     * endpoint on this, so a branch that skips the ceremony or charges a
     * different budget hands back the oracle by another route.
     *
     * The provider SEND may legitimately differ: Task 1 already established
     * the decoy pattern, where the outbox row is created and charged but the
     * worker declines to deliver. That difference is invisible to the caller;
     * a throttle or outbox difference would not be.
     */
    expect($taken)->toEqual($fresh);
});

it('does not attach another user credential when the identifier is taken', function (): void {
    AuthIdentifier::create([
        'user_id' => 99,
        'type' => 'email',
        'value' => 'taken@acme.example',
        'verified_at' => now(),
    ]);

    enrollFirstCredential(firstCredentialRequest(2, 'taken@acme.example'));

    /*
     * Neutral to the caller, but it must not silently bind someone else's
     * identifier to the new user, nor mint a credential for an enrollment that
     * did not happen.
     */
    expect(AuthIdentifier::query()->where('value', 'taken@acme.example')->count())->toBe(1)
        ->and(AuthIdentifier::query()->where('value', 'taken@acme.example')->value('user_id'))->toBe(99)
        ->and(AuthCredential::query()->where('user_id', 2)->count())->toBe(0);
});

it('leaves no credential or ceremony behind when the identifier cannot be claimed', function (): void {
    AuthIdentifier::create([
        'user_id' => 99,
        'type' => 'email',
        'value' => 'taken@acme.example',
        'verified_at' => now(),
    ]);

    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
    app(FirstCredentialEnrollment::class)->enroll(firstCredentialRequest(2, 'taken@acme.example'));

    /*
     * Asserted BEFORE the worker runs: a decoy outbox row is deleted on
     * delivery, so a correct implementation could not satisfy this afterwards.
     * The flag lives on the verification record; the outbox carries it inside
     * the encrypted payload.
     */
    $decoyed = DB::table('auth_identifier_verifications')->where('is_decoy', true)->exists();

    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);

    foreach (DB::table('auth_identifier_verification_outbox')->pluck('opaque_id') as $opaqueId) {
        app(VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    /*
     * Partial success is the dangerous outcome: a credential minted for a user
     * who owns no identifier can never be used, and a ceremony sent to an
     * address the caller does not control is an unsolicited message.
     */
    expect(AuthCredential::query()->where('user_id', 2)->count())->toBe(0)
        // No message reaches an address the caller does not control, even
        // though the ceremony was charged and an outbox row was written --
        // that is the decoy shape, and it is what keeps the branches level.
        ->and($decoyed)->toBeTrue()
        ->and($delivery->sent)->toBe([]);
});

it('is idempotent when the same enrollment is retried', function (): void {
    enrollFirstCredential();
    [$second, ] = enrollFirstCredential();

    /*
     * A retry -- a duplicated request, a client that resent -- must not produce
     * a second credential. PasswordFactor allows exactly one active credential,
     * so a naive second write would either duplicate or refuse loudly.
     */
    expect($second)->toBe(FirstCredentialResult::Accepted)
        ->and(AuthIdentifier::query()->where('value', 'ada@acme.example')->count())->toBe(1)
        ->and(AuthCredential::query()->where('user_id', 1)->whereNull('disabled_at')->count())->toBe(1);
});

it('re-enables a disabled credential rather than stranding the user', function (): void {
    enrollFirstCredential();
    AuthCredential::query()->where('user_id', 1)->update(['disabled_at' => now()]);

    [$result, ] = enrollFirstCredential(firstCredentialRequest(1, 'ada@acme.example', 'second-password'));

    $active = AuthCredential::query()->where('user_id', 1)->whereNull('disabled_at')->get();

    expect($result)->toBe(FirstCredentialResult::Accepted)
        ->and($active)->toHaveCount(1)
        ->and(Hash::check('second-password', (string) $active->first()?->secret))->toBeTrue();
});


it('charges the ceremony throttle dimension', function (): void {
    enrollFirstCredential();

    /*
     * Ceremony volume is a different budget from login volume; the dimension
     * exists so enrollment cannot consume the login issuance allowance.
     */
    expect(DB::table('auth_throttle_counters')->where('dimension', 'ceremony')->sum('count'))
        ->toBeGreaterThan(0)
        ->and(DB::table('auth_throttle_counters')->where('dimension', 'identifier')->sum('count'))
        ->toBe(0);
});

