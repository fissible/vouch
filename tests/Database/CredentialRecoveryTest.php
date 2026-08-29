<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryOutcome;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\InterceptingPasswordFactor;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

uses(DatabaseMigrations::class);



/*
 * DatabaseMigrations rather than RefreshDatabase: the ordering contract is about
 * COMMITS, and RefreshDatabase wraps each test in an uncommitted transaction
 * that a second connection cannot see. The commit probe below would read false
 * unconditionally under it. The existing multi-connection contention tests make
 * the same trade.
 */

/*
 * 2.3d Task 2. Composition: recovery-specific proof -> GraceGuard ->
 * PasswordFactor::enroll(). The proof is its OWN ceremony, not Task 1's: an
 * identifier-verification code attests control for verification, and letting it
 * also open a password-reset capability would be an authority expansion across
 * ceremonies. "Reuse grace" means reuse the post-proof capability, not the proof.
 *
 * The parts that are not composition, and therefore carry the tests, are the
 * credential-change ordering contract and the decided assurance policy, which
 * the plan requires proven in BOTH configured modes.
 */

function recoveryRequest(string $value): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function recoverableUser(int $userId = 1, string $value = 'ada@acme.example'): AuthIdentifier
{
    $identifier = AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);

    app(PasswordFactor::class)->enroll($userId, ['password' => 'old-password']);

    return $identifier;
}

/** Recover the proof through the recovery outbox and the bound OtpDelivery. */
function requestRecoveryAndDeliver(string $value): ArrayOtpDelivery
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    app(CredentialRecovery::class)->request(recoveryRequest($value));

    foreach (DB::table('auth_recovery_proof_outbox')->pluck('opaque_id') as $opaqueId) {
        app(RecoveryProofOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery;
}

/** Open grace for $host and return the live proof code that opened it. */
function openedGrace(string $host = 'host-session-1'): void
{
    $code = requestRecoveryAndDeliver('ada@acme.example')->lastCode();
    app(CredentialRecovery::class)->redeem(recoveryRequest('ada@acme.example'), $code, $host);
}

/** A live non-grace session for $userId that recovery must revoke. */
function liveSession(int $userId, string $binding): AuthSession
{
    return AuthSession::create([
        'user_id' => $userId,
        'session_binding' => $binding,
        'amr' => ['pwd'],
        'acr' => 'aal1',
        'weakest_satisfied_at' => now(),
    ]);
}

/**
 * Substitute the password factor recovery composes with. FactorRegistry is
 * write-once by design -- replacing a driver silently would let a permissive
 * implementation displace a restrictive one -- so the seam is a contextual
 * binding on the recovery service's own dependency, not a registry mutation.
 */
function interceptMutation(?Closure $before = null, bool $throw = false): InterceptingPasswordFactor
{
    $factor = new InterceptingPasswordFactor(app(PasswordFactor::class), $before, $throw);

    app()->when(CredentialRecovery::class)->needs(Factor::class)->give(fn (): Factor => $factor);
    app()->forgetInstance(CredentialRecovery::class);

    return $factor;
}

/**
 * Read revocation state through a connection that cannot see another
 * connection's uncommitted writes. SQLite-only, like ThrottleSchemaTest's
 * metadata assertions; the matrix legs cover the other engines.
 */
function revokedOnAnIndependentConnection(int $sessionId): bool
{
    if (DB::getDriverName() !== 'sqlite') {
        return AuthSession::query()->whereKey($sessionId)->value('revoked_at') !== null;
    }

    /*
     * A second connection to ':memory:' opens a NEW empty database, so the
     * probe would fail on a missing table rather than answer the question.
     * The contention suite skips itself for the same reason.
     */
    $path = (string) (getenv('VOUCH_SQLITE_PATH') ?: ':memory:');

    if ($path === ':memory:') {
        throw new RuntimeException(
            'The commit-ordering probe needs a file-backed database; set VOUCH_SQLITE_PATH.',
        );
    }

    $pdo = new PDO('sqlite:' . $path);
    $statement = $pdo->prepare('select revoked_at from auth_sessions where id = ?');
    $statement->execute([$sessionId]);

    return ($statement->fetchColumn() ?: null) !== null;
}

function currentPasswordSecret(): string
{
    /** @var string $secret */
    $secret = AuthCredential::query()
        ->where('user_id', 1)->where('type', 'password')
        ->whereNull('disabled_at')->value('secret');

    return $secret;
}

it('is enumeration-safe for unknown and unverified identifiers', function (): void {
    recoverableUser();
    AuthIdentifier::create([
        'user_id' => 2,
        'type' => 'email',
        'value' => 'unverified@acme.example',
        'verified_at' => null,
    ]);

    $recovery = app(CredentialRecovery::class);

    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    /*
     * request() returns void deliberately -- there is nothing for it to leak.
     * So neutrality has to be measured in observable EFFECTS. Comparing the
     * return values would compare three nulls and pass against any
     * implementation at all, which is what this test used to do.
     */
    $observe = function (string $value) use ($recovery): array {
        $before = [
            'ceremony' => (int) DB::table('auth_throttle_counters')->where('dimension', 'ceremony')->sum('count'),
            'proofs' => DB::table('auth_recovery_proofs')->count(),
            'outbox' => DB::table('auth_recovery_proof_outbox')->count(),
        ];

        $recovery->request(recoveryRequest($value));

        return [
            'ceremony' => (int) DB::table('auth_throttle_counters')->where('dimension', 'ceremony')->sum('count') - $before['ceremony'],
            'proofs' => DB::table('auth_recovery_proofs')->count() - $before['proofs'],
            'outbox' => DB::table('auth_recovery_proof_outbox')->count() - $before['outbox'],
        ];
    };

    $known = $observe('ada@acme.example');
    $mintedForKnown = stringValue(DB::table('auth_recovery_proof_outbox')->latest('id')->value('opaque_id'));

    $unverified = $observe('unverified@acme.example');
    $unknown = $observe('nobody@acme.example');

    // Positive control on the ORIGINAL known request, not a fresh one.
    app(RecoveryProofOutboxDelivery::class)->deliver($mintedForKnown);

    expect($known)->toEqual($unverified)
        ->and($unverified)->toEqual($unknown)
        ->and($known['outbox'])->toBeGreaterThan(0)
        ->and($delivery->sent)->toHaveCount(1);
});

it('opens grace rather than minting a reset credential', function (): void {
    recoverableUser();
    $code = requestRecoveryAndDeliver('ada@acme.example')->lastCode();

    $outcome = app(CredentialRecovery::class)
        ->redeem(recoveryRequest('ada@acme.example'), $code, 'host-session-1');

    expect($outcome)->toBe(CredentialRecoveryOutcome::GraceOpened)
        ->and(app(GraceGuard::class)->activeFor('host-session-1'))->not->toBeNull()
        ->and(AuthCredential::query()->where('user_id', 1)->count())->toBe(1);
});

it('consumes the proof exactly once', function (): void {
    recoverableUser();
    $code = requestRecoveryAndDeliver('ada@acme.example')->lastCode();
    $recovery = app(CredentialRecovery::class);

    expect($recovery->redeem(recoveryRequest('ada@acme.example'), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened)
        ->and($recovery->redeem(recoveryRequest('ada@acme.example'), $code, 'host-session-2'))
        ->toBe(CredentialRecoveryOutcome::Refused);
});

it('will not redeem an identifier verification proof', function (): void {
    $identifier = recoverableUser();

    /*
     * Task 1's ceremony attests control for VERIFICATION. Redeeming it here
     * would expand its authority into password recovery, which is the
     * cross-ceremony confusion the separate proof stores exist to prevent.
     */
    $verification = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $verification);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
    app(\Fissible\Vouch\Verification\IdentifierVerifier::class)->request(
        new \Fissible\Vouch\Verification\IdentifierVerificationRequest(
            type: 'email',
            submittedIdentifier: 'ada@acme.example',
            tenantId: null,
            clientIp: '203.0.113.10',
        ),
    );

    foreach (DB::table('auth_identifier_verification_outbox')->pluck('opaque_id') as $opaqueId) {
        app(\Fissible\Vouch\Verification\VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    expect(app(CredentialRecovery::class)
        ->redeem(recoveryRequest('ada@acme.example'), $verification->lastCode(), 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and(app(GraceGuard::class)->activeFor('host-session-1'))->toBeNull();
});

it('will not open grace for an identifier the proof was not sent to', function (): void {
    recoverableUser(1, 'ada@acme.example');
    recoverableUser(2, 'bob@acme.example');

    $adaCode = requestRecoveryAndDeliver('ada@acme.example')->lastCode();

    /*
     * A lookup keyed on the code alone, trusting the submitted identifier for
     * the target user, would open grace over Bob's account here. Refusing must
     * also not consume Ada's proof: refusing-by-consuming would let anyone
     * cancel a pending recovery for an address they do not control.
     */
    $recovery = app(CredentialRecovery::class);

    expect($recovery->redeem(recoveryRequest('bob@acme.example'), $adaCode, 'host-session-2'))
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and(app(GraceGuard::class)->activeFor('host-session-2'))->toBeNull()
        ->and($recovery->redeem(recoveryRequest('ada@acme.example'), $adaCode, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('commits revocation before mutating, and reports failure without undoing it', function (): void {
    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Proving the revocation COMMITTED needs a second connection to one file-backed database.',
        );
    }

    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace();

    /*
     * The failure is injected INSIDE the mutation step, so an implementation
     * that validated input first and revoked second cannot pass. The contract's
     * chosen ordering says revocation stands, the old credential still works,
     * and the operation reports failure rather than partial success.
     */
    $factor = interceptMutation(
        before: fn (): bool => revokedOnAnIndependentConnection($sibling->id),
        throw: true,
    );

    $outcome = app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    /*
     * observed === true is the ordering proof, and it is read on a SEPARATE
     * connection so it proves the revocation was COMMITTED, not merely written
     * inside an open transaction. The contract's whole point is that the two
     * steps cannot share a transaction: a rollback would undo both, and the
     * same-connection read cannot tell the difference.
     */
    expect($factor->observed)->toBeTrue()
        ->and($outcome)->toBe(CredentialRecoveryOutcome::Refused)
        ->and($sibling->refresh()->revoked_at)->not->toBeNull()
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeTrue()
        ->and(app(GraceGuard::class)->activeFor('host-session-1'))->not->toBeNull();
});

it('refuses a reset without an active matching grace capability', function (): void {
    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace('host-session-1');

    /*
     * Every other reset test opens valid grace first, so without this an
     * implementation that never checks grace at all passes the whole suite.
     * A reset presented on a different host session must not borrow it.
     */
    $recovery = app(CredentialRecovery::class);

    expect($recovery->reset('host-session-unknown', 'new-password-value'))
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeTrue()
        ->and($sibling->refresh()->revoked_at)->toBeNull();
});

it('refuses a reset once its grace capability has lapsed', function (): void {
    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace();

    /*
     * Grace deadlines are compared by a SQL predicate against the database
     * clock, deliberately, so a security window does not drift with whatever
     * skew exists between the application and the database. Advancing
     * Laravel's clock therefore expires nothing; the row itself must be aged.
     */
    DB::table('auth_sessions')
        ->whereNotNull('recovery_grace_expires_at')
        ->update(['recovery_grace_expires_at' => '2000-01-01 00:00:00']);

    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value'))
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeTrue()
        ->and($sibling->refresh()->revoked_at)->toBeNull();
});

it('revokes again after the mutation commits, catching the stated race', function (): void {
    recoverableUser();
    openedGrace();

    /*
     * The stated race: between the two commits a login on the OLD credential
     * can create a session the first revocation never saw. This creates exactly
     * that session at the mutation boundary; only a second revocation pass
     * catches it. Without one, this session survives.
     */
    $raced = null;
    $factor = interceptMutation(before: function () use (&$raced): void {
        $raced = liveSession(1, str_repeat('r', 64));
    });

    $outcome = app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    expect($outcome)->toBe(CredentialRecoveryOutcome::Reset)
        ->and($factor->enrollCalls)->toBe(1)
        ->and($raced?->refresh()->revoked_at)->not->toBeNull()
        // Positive control: the reset must actually have replaced the credential.
        ->and(Hash::check('new-password-value', currentPasswordSecret()))->toBeTrue()
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeFalse();
});

it('keeps the acting grace session and revokes the others', function (): void {
    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace();
    $grace = app(GraceGuard::class)->activeFor('host-session-1');

    app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    expect($sibling->refresh()->revoked_at)->not->toBeNull()
        ->and($sibling->refresh()->revoked_reason)->toBe(RevokedReason::PasswordChanged)
        ->and($grace?->refresh()->revoked_at)->toBeNull();
});

it('never authenticates the user', function (): void {
    recoverableUser();
    openedGrace();

    app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    /*
     * Recovery re-enrols a credential; it does not authenticate. Asserting on
     * counts alone would pass if grace were swapped for an authenticated row,
     * so assert the surviving session is still the constrained grace capability
     * and that no attempt or token assurance was created.
     */
    $live = AuthSession::query()->whereNull('revoked_at')->get();

    expect($live)->toHaveCount(1)
        ->and($live->first()?->recovery_grace_expires_at)->not->toBeNull()
        ->and(DB::table('auth_attempts')->count())->toBe(0)
        ->and(DB::table('auth_token_assurances')->count())->toBe(0);
});

it('records post-reset assurance as single-factor by default', function (): void {
    recoverableUser();
    openedGrace();

    app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    /*
     * Decided default (b): inbox control is ONE possession factor, recorded
     * honestly, so per-route step-up still guards anything sensitive. Full
     * assurance from inbox control alone deliberately does not ship.
     */
    $session = AuthSession::query()->whereNull('revoked_at')->first();

    expect($session)->not->toBeNull()
        ->and($session?->acr)->toBeNull()
        ->and($session?->recovery_grace_expires_at)->not->toBeNull();
});

it('requires an enabled second factor during reset when configured to', function (): void {
    Config::set('vouch.recovery.require_second_factor', true);
    recoverableUser();
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(1, ['label' => 'ada@acme.example']);
    openedGrace();

    /*
     * Mode (a): stronger for the account, but it recreates the lockout recovery
     * codes exist to solve. The plan requires BOTH modes proven, not merely
     * offered, so this is the paired proof for the default above.
     */
    /*
     * Grace must survive the refusal. Consuming or revoking it here would
     * strand the user: they hold a valid proof, are told to present a second
     * factor, and have nothing left to present it against.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value'))
        ->toBe(CredentialRecoveryOutcome::SecondFactorRequired)
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeTrue()
        ->and(app(GraceGuard::class)->activeFor('host-session-1'))->not->toBeNull();
});

it('does not require a second factor the account does not have', function (): void {
    Config::set('vouch.recovery.require_second_factor', true);
    recoverableUser();
    openedGrace();

    /*
     * The paired branch of mode (a). Requiring a factor the account lacks would
     * be the lockout the policy explicitly refuses to create.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value'))
        ->toBe(CredentialRecoveryOutcome::Reset)
        ->and(Hash::check('new-password-value', currentPasswordSecret()))->toBeTrue();
});

it('ignores a disabled second factor when deciding whether to require one', function (): void {
    Config::set('vouch.recovery.require_second_factor', true);
    recoverableUser();
    $totp = app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    AuthCredential::query()->whereKey($totp->id)->update(['disabled_at' => now()]);
    openedGrace();

    /*
     * A disabled factor cannot be presented, so treating it as present would
     * lock the account out of its own recovery.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value'))
        ->toBe(CredentialRecoveryOutcome::Reset);
});
