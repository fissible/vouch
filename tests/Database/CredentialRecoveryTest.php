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
use Illuminate\Support\Facades\Exceptions;
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
     *
     * #35 amended the expected value only. The ordering this test pins did not
     * change; the outcome stopped being spelled the same as an unauthorized
     * caller's refusal.
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
        ->and($outcome->outcome)->toBe(CredentialRecoveryOutcome::CredentialChangeFailed)
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

    expect($recovery->reset('host-session-unknown', 'new-password-value')->outcome)
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

    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
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

    expect($outcome->outcome)->toBe(CredentialRecoveryOutcome::Reset)
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
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
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
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
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
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::Reset);
});

/*
 * #35. The ordering above is the security contract and stays: siblings are
 * revoked and that revocation is committed BEFORE the credential mutates, so
 * a stale session cannot outlive the reset that was meant to end it.
 *
 * What was wrong was the vocabulary, not the order. A mutation that fails
 * after that commit returned CredentialRecoveryOutcome::Refused -- the same
 * value returned to a caller who was never authorized at all. So the caller
 * could not distinguish "nothing happened" from "you are authorized, your
 * other sessions are gone, and your password did not change", and the second
 * of those needs different handling: the user must retry, and an operator
 * needs to know the credential store failed.
 *
 * CredentialChangeFailed is scoped precisely, because a looser promise would
 * repeat the bug in a new place:
 *
 *   authorized; sibling sessions were revoked and committed;
 *   Vouch-owned credential writes rolled back.
 *
 * reset() returns a CredentialResetResult rather than the bare enum, for the
 * same reason the outcome exists at all. A reset whose credential committed but
 * whose token cleanup failed is not an ordinary Reset: the tokens that cited
 * the replaced password may still be live at their issuer. That residual has
 * nowhere to live on an enum, so every assertion here reads ->outcome, and the
 * paired issuer tests at the end of this file pin the residual itself.
 * driverFailures carries structured issuer/token identities, not exception
 * text, because an operator needs to know WHICH token was stranded.
 *
 * "Rolled back" is a real requirement, not a description. A caught Throwable
 * does not by itself prove the credential is unchanged: the failure can land
 * after the driver already wrote. So the mutation phase runs in its own
 * transaction, separate from and after the revocation's committed one, and the
 * post-write tests below are what force that. There may have been zero
 * siblings; the outcome says a revocation pass ran, not that it revoked rows.
 *
 * The discriminating axis these tests exist to hold is WHERE the failure
 * happened. Refusals that occur before the revocation pass -- no grace, a
 * required second factor -- keep the ordinary vocabulary AND must leave
 * siblings alone. An implementation that renames the catch block without
 * drawing that line passes none of the pairs below.
 */

it('distinguishes a reset that failed from one that was refused', function (): void {
    recoverableUser();
    openedGrace();

    interceptMutation(throw: true);

    $failed = app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    // The same call with no grace behind it: refused before anything was
    // authorized. The two must not share a value.
    $refused = app(CredentialRecovery::class)->reset('host-session-never-opened', 'new-password-value');

    expect($failed->outcome)->toBe(CredentialRecoveryOutcome::CredentialChangeFailed)
        ->and($failed->outcome)->not->toBe(CredentialRecoveryOutcome::Refused)
        ->and($failed->outcome)->not->toBe(CredentialRecoveryOutcome::Reset)
        ->and($refused->outcome)->toBe(CredentialRecoveryOutcome::Refused);
});

it('leaves the old credential usable when the reset fails', function (): void {
    recoverableUser();
    openedGrace();

    interceptMutation(throw: true);

    /*
     * The failure outcome is only honest if the credential really did not
     * change. Asserting the enum alone would accept an implementation that
     * mutated and then reported failure.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::CredentialChangeFailed)
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeTrue()
        ->and(Hash::check('new-password-value', currentPasswordSecret()))->toBeFalse();
});

it('leaves siblings revoked after the mutation failed', function (): void {
    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace();

    interceptMutation(throw: true);

    /*
     * #35 asked whether the revocation should be undone. It should not: the
     * window it closes is real, and reversing the order re-opens it. The new
     * outcome exists so the caller learns this happened, not so it stops
     * happening.
     *
     * Final state only. The ordering itself is pinned by the
     * independent-connection probe above, which is the one that can tell a
     * committed revocation from one merely written first.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::CredentialChangeFailed)
        ->and($sibling->refresh()->revoked_at)->not->toBeNull()
        ->and($sibling->refresh()->revoked_reason)->toBe(RevokedReason::PasswordChanged);
});

it('does not revoke siblings for a reset refused before authorization', function (): void {
    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));

    /*
     * The paired negative. An implementation that revokes first and decides
     * afterwards would return the failure outcome here too, and would have
     * destroyed a live session on behalf of a caller holding nothing.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-never-opened', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and($sibling->refresh()->revoked_at)->toBeNull();
});

it('does not revoke siblings when a second factor is required', function (): void {
    Config::set('vouch.recovery.require_second_factor', true);
    recoverableUser();
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(1, ['label' => 'ada@acme.example']);
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace();

    /*
     * SecondFactorRequired returns before the revocation pass, so it is the
     * second early exit that must keep its own vocabulary and its own
     * no-side-effects promise.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::SecondFactorRequired)
        ->and($sibling->refresh()->revoked_at)->toBeNull();
});

it('keeps the grace window open when the reset fails', function (): void {
    recoverableUser();
    openedGrace();

    interceptMutation(throw: true);

    /*
     * A user told to retry needs something to retry against. Consuming grace
     * on an operational failure would strand them exactly as consuming it on
     * a second-factor refusal would.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::CredentialChangeFailed)
        ->and(app(GraceGuard::class)->activeFor('host-session-1'))->not->toBeNull();
});

it('reports the failure that produced the outcome', function (): void {
    Exceptions::fake();

    recoverableUser();
    openedGrace();

    interceptMutation(throw: true);

    /*
     * No AuditSink driver exists yet (2.4), so report() IS the operator path
     * today. The outcome tells the caller to retry; this tells whoever runs
     * the system that the credential store threw.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::CredentialChangeFailed);

    /*
     * By identity, not by class. Asserting RuntimeException alone would pass on
     * any unrelated reported exception, including one raised by a later
     * implementation for a different reason.
     */
    Exceptions::assertReported(fn (RuntimeException $reported): bool =>
        $reported->getMessage() === 'Credential mutation failed after revocation committed.');
});

it('still reports success as success', function (): void {
    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace();

    /*
     * The new case must not widen. A reset that works keeps its own value,
     * still revokes siblings, and still changes the credential.
     */
    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::Reset)
        ->and(Hash::check('new-password-value', currentPasswordSecret()))->toBeTrue()
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('rolls back a credential written before the failure', function (): void {
    recoverableUser();
    $sibling = liveSession(1, str_repeat('s', 64));
    openedGrace();

    /*
     * The failure lands AFTER the driver already wrote the new password. This
     * is the case a catch block alone cannot handle and the one that decides
     * whether CredentialChangeFailed is honest: without a transaction around
     * the mutation phase, the outcome says "rolled back" while the account's
     * password has silently changed to a value the user never saw confirmed.
     *
     * The revocation must still stand. It committed in its own transaction
     * before this one opened, so rolling the mutation back cannot take it with
     * it -- and an implementation that wrapped both together would fail here.
     */
    $factor = new InterceptingPasswordFactor(app(PasswordFactor::class), throwAfter: true);
    app()->when(CredentialRecovery::class)->needs(Factor::class)->give(fn (): Factor => $factor);
    app()->forgetInstance(CredentialRecovery::class);

    expect(app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value')->outcome)
        ->toBe(CredentialRecoveryOutcome::CredentialChangeFailed)
        ->and($factor->enrollCalls)->toBe(1)
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeTrue()
        ->and(Hash::check('new-password-value', currentPasswordSecret()))->toBeFalse()
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('keeps exactly one active password after a rolled-back reset', function (): void {
    recoverableUser();
    openedGrace();

    /*
     * enroll(replace: true) disables the old credential and writes a new one.
     * A rollback that restored the secret but left both rows active, or left
     * the old one disabled, would satisfy a Hash::check assertion while leaving
     * the account in a state it was never in.
     */
    $factor = new InterceptingPasswordFactor(app(PasswordFactor::class), throwAfter: true);
    app()->when(CredentialRecovery::class)->needs(Factor::class)->give(fn (): Factor => $factor);
    app()->forgetInstance(CredentialRecovery::class);

    app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    expect(AuthCredential::query()->where('user_id', 1)->where('type', 'password')->count())->toBe(1)
        ->and(AuthCredential::query()->where('user_id', 1)->where('type', 'password')
            ->whereNull('disabled_at')->count())->toBe(1);
});

/**
 * A public residual names WHICH token at WHICH issuer, and nothing else.
 *
 * get_object_vars() from outside class scope sees public properties only, which
 * is the point: json_encode() and print_r() can both be silenced, by
 * JsonSerializable and __debugInfo respectively, while a public property still
 * hands the driver's exception text to the caller. Measured as surviving both
 * string checks, so the property set is what gets asserted.
 *
 * @param list<object> $failures
 */
function expectIdentityOnly(array $failures): void
{
    foreach ($failures as $failure) {
        $properties = array_keys(get_object_vars($failure));
        sort($properties);

        // The SET is the contract; the declaration order is not. Comparing
        // unsorted would fail a correct implementation that declares tokenKey
        // first, which is a refusal this test has no business making.
        expect($properties)->toBe(['issuerKey', 'tokenKey']);
    }
}

/** Seed a human token whose recorded proof cites user 1's active password. */
function tokenCitingPassword(string $tokenKey, string $issuerKey = 'sanctum'): void
{
    app(\Fissible\Vouch\Tokens\TokenAssuranceRecord::class)->store(
        $issuerKey,
        $tokenKey,
        \Fissible\Vouch\Tokens\SubjectKey::forConfiguredUser(1),
        null,
        \Fissible\Vouch\Tokens\ActorKind::Human,
        [new \Fissible\Vouch\Kernel\Factor\SatisfiedFactor(
            'password',
            stringValue(AuthCredential::query()->where('user_id', 1)->where('type', 'password')
                ->whereNull('disabled_at')->value('id')),
            \Fissible\Vouch\Kernel\Factor\FactorKind::Knowledge,
            \Fissible\Vouch\Kernel\Factor\FactorStrength::Knowledge,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        )],
    );
}

it('surfaces a driver residual when the reset committed', function (): void {
    recoverableUser();

    // The proof cites the password this reset replaces, so this token is the
    // one the mutation must ask the issuer to revoke.
    tokenCitingPassword('token-key-1');

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
    );
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );
    app()->forgetInstance(CredentialRecovery::class);

    openedGrace();

    /*
     * Issuer revocation runs in afterCommit, past the point any transaction can
     * undo. This is NOT the rollback case and must not borrow its outcome: the
     * password really did change, so the reset succeeded. What must not happen
     * is a clean Reset, because a token citing the old password may still work.
     *
     * attempted proves the contested path ran, so this cannot become a demand
     * for something unreachable.
     */
    $result = app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    expect($issuer->attempted)->toBe(['token-key-1'])
        ->and($issuer->revoked)->toBe([])
        ->and($result->outcome)->toBe(CredentialRecoveryOutcome::Reset)
        ->and(Hash::check('new-password-value', currentPasswordSecret()))->toBeTrue()
        ->and($result->driverFailures)->not->toBe([])
        ->and($result->driverFailures[0]->issuerKey)->toBe('sanctum')
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1');

    /*
     * Identities, not diagnostics. CredentialMutation's INTERNAL failure object
     * carries the driver's exception text by design, and its own tests require
     * that -- but returning that object unmodified from a service method puts
     * a third party's error string on the caller's result, where it can reach a
     * response body or a log the operator did not choose. Returning the
     * internal object unchanged passes every identity assertion above, so the
     * absence has to be asserted separately.
     */
    expect(json_encode($result->driverFailures))->not->toContain('Issuer unreachable.')
        ->and(print_r($result->driverFailures, true))->not->toContain('Issuer unreachable.');

    expectIdentityOnly($result->driverFailures);
});

it('reports a driver residual alongside a failed reset', function (): void {
    recoverableUser();

    tokenCitingPassword('token-key-1');

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
    );
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );

    openedGrace();

    $factor = new InterceptingPasswordFactor(app(PasswordFactor::class), throwAfter: true);
    app()->when(CredentialRecovery::class)->needs(Factor::class)->give(fn (): Factor => $factor);
    app()->forgetInstance(CredentialRecovery::class);

    /*
     * The residual and the outcome are independent. Token invalidation commits
     * with the revocation pass, so its driver failure is real whether or not
     * the credential mutation then succeeded. Populating driverFailures only
     * when the outcome is Reset hides the residual exactly when an operator
     * most needs it -- and passes every success-path residual test, measured.
     */
    $result = app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    expect($issuer->attempted)->toBe(['token-key-1'])
        ->and($result->outcome)->toBe(CredentialRecoveryOutcome::CredentialChangeFailed)
        ->and(Hash::check('old-password', currentPasswordSecret()))->toBeTrue()
        ->and($result->driverFailures)->not->toBe([])
        ->and($result->driverFailures[0]->issuerKey)->toBe('sanctum')
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1');

    // The failure path needs the same diagnostic guarantee as the success
    // path. Leaking raw driver text only when the reset FAILED survived the
    // whole suite, because this test checked identities and stopped there.
    expectIdentityOnly($result->driverFailures);
});

it('reports no residual when the reset cleaned up completely', function (): void {
    recoverableUser();

    tokenCitingPassword('token-key-1');

    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer('sanctum');
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );
    app()->forgetInstance(CredentialRecovery::class);

    openedGrace();

    /*
     * The paired negative. Without it an implementation that always reports a
     * residual passes the test above while telling every caller their tokens
     * are in doubt.
     */
    $result = app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    expect($issuer->revoked)->toBe(['token-key-1'])
        ->and($result->outcome)->toBe(CredentialRecoveryOutcome::Reset)
        ->and($result->driverFailures)->toBe([]);
});

it('names every token a reset could not clean up', function (): void {
    recoverableUser();

    /*
     * Two issuers, one shared token key, and one token that cleans up fine.
     *
     * A token key is only unique WITHIN an issuer, so a residual keyed on the
     * token alone silently drops one of the two 'shared' entries -- an operator
     * reconciles one system and leaves the other live. And reporting a whole
     * batch as failed because part of it failed sends them after 'good', which
     * was revoked correctly. Both survived every same-issuer fixture.
     */
    tokenCitingPassword('shared', 'alpha');
    tokenCitingPassword('shared', 'beta');
    tokenCitingPassword('good', 'alpha');

    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([
            failingOnSharedToken('alpha'),
            failingOnSharedToken('beta'),
        ]),
    );
    app()->forgetInstance(CredentialRecovery::class);

    openedGrace();

    $result = app(CredentialRecovery::class)->reset('host-session-1', 'new-password-value');

    // Pairs, not keys: the identity is (issuer, token) together.
    $pairs = array_map(
        fn (object $failure): array => [$failure->issuerKey, $failure->tokenKey],
        $result->driverFailures,
    );
    sort($pairs);

    expect($result->outcome)->toBe(CredentialRecoveryOutcome::Reset)
        ->and($pairs)->toBe([['alpha', 'shared'], ['beta', 'shared']]);
});

it('does not carry one reset\'s residual into the next', function (): void {
    recoverableUser();
    tokenCitingPassword('token-key-1');

    // Throws on the FIRST revoke only, so the second reset cleans up fully.
    $issuer = new \Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer(
        'sanctum',
        new RuntimeException('Issuer unreachable.'),
        throwOnCall: 1,
    );
    app()->instance(
        \Fissible\Vouch\Tokens\TokenIssuerRegistry::class,
        new \Fissible\Vouch\Tokens\TokenIssuerRegistry([$issuer]),
    );
    app()->forgetInstance(CredentialRecovery::class);

    $recovery = app(CredentialRecovery::class);

    openedGrace();
    $first = $recovery->reset('host-session-1', 'new-password-value');

    tokenCitingPassword('token-key-2');
    openedGrace('host-session-2');
    $second = $recovery->reset('host-session-2', 'another-password-value');

    /*
     * A residual accumulated on a service-level collection rather than built
     * per call reports the first failure again on every later call, telling an
     * operator to chase a token that was already reconciled. Same service
     * instance deliberately: a fresh one would hide it.
     */
    expect($first->driverFailures)->not->toBe([])
        ->and($second->outcome)->toBe(CredentialRecoveryOutcome::Reset)
        ->and($second->driverFailures)->toBe([]);
});
