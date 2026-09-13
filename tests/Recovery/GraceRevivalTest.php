<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthRecoveryProof;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryOutcome;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * Issue #36 -- a revoked session row is terminal, and grace may not revive it.
 *
 * GraceGuard::start() wrote with updateOrInsert keyed on the binding ALONE and
 * set revoked_at and revoked_reason to null. Measured before any of this:
 * starting grace on a binding whose row was revoked for PasswordChanged left
 * revoked_at null, revoked_reason null, and user_id REASSIGNED from 7 to 9.
 * The session came back to life, its audit record was erased, and the row named
 * a different subject than the one whose session it had been.
 *
 * The class already disagreed with itself about this. expireIfLapsed carries a
 * whereNull('revoked_at') guard and a comment defending it -- "if the row was
 * already admin_revoked, the update affects no rows and the existing reason
 * stands" -- while start() nulled both fields unguarded.
 *
 * Since #30 the consequence is sharper. A revoked session's ownership marker
 * holds that row's id, so reviving the row makes marker and record agree again
 * and ValidatesVouchSession passes a session whose row now names someone else.
 *
 * The frozen rule: revocation is an ownership and audit boundary, not a
 * temporary state. A revoked binding opens no grace, the revocation fields and
 * the subject stay as they are, redeem() reports an ordinary refusal rather
 * than claiming GraceOpened, and no error is raised for what is an expected
 * recovery condition.
 */

function revivalBinding(string $hostSessionId = 'host-session-1'): string
{
    return SessionBinding::for($hostSessionId, BindingDomain::Session);
}

/** A session row already ended, with the reason that ended it. */
function revokedSession(RevokedReason $reason, int $userId = 7, string $host = 'host-session-1'): AuthSession
{
    return AuthSession::create([
        'session_binding' => revivalBinding($host),
        'user_id' => $userId,
        'amr' => ['password'],
        'revoked_at' => now()->subMinutes(5),
        'revoked_reason' => $reason,
    ]);
}

/** @return array{revoked: bool, reason: string|null, user_id: int, grace: bool} */
function sessionStateFor(string $host = 'host-session-1'): array
{
    $row = requiredRow(DB::table('auth_sessions')->where('session_binding', revivalBinding($host))->first());

    return [
        'revoked' => $row->revoked_at !== null,
        'reason' => $row->revoked_reason === null ? null : stringValue($row->revoked_reason),
        'user_id' => (int) stringValue($row->user_id),
        'grace' => app(GraceGuard::class)->activeFor($host) instanceof AuthSession,
    ];
}

/* ---- the guard itself --------------------------------------------------- */

it('opens no grace on a session revoked by a password change', function (): void {
    /*
     * The case the defect was found on. A password change is exactly when a
     * session must stay dead: reviving it hands back the access the change was
     * made to remove.
     */
    revokedSession(RevokedReason::PasswordChanged);

    app(GraceGuard::class)->start('host-session-1', 7);

    expect(sessionStateFor())->toBe([
        'revoked' => true,
        'reason' => RevokedReason::PasswordChanged->value,
        'user_id' => 7,
        'grace' => false,
    ]);
});

it('opens no grace on a session an administrator revoked', function (): void {
    /*
     * The reason expireIfLapsed already guards for, named in its own comment.
     * The two methods in one class must not disagree about whether a
     * revocation reason survives.
     */
    revokedSession(RevokedReason::AdminRevoked);

    app(GraceGuard::class)->start('host-session-1', 7);

    expect(sessionStateFor())->toBe([
        'revoked' => true,
        'reason' => RevokedReason::AdminRevoked->value,
        'user_id' => 7,
        'grace' => false,
    ]);
});

it('does not reassign a revoked session to whoever is recovering', function (): void {
    /*
     * Measured on the unfixed code: the row moved from user 7 to user 9. That
     * is worse than revival on its own -- the binding survives, so a session
     * established for one subject ends up naming another.
     */
    revokedSession(RevokedReason::PasswordChanged, userId: 7);

    app(GraceGuard::class)->start('host-session-1', 9);

    expect(sessionStateFor()['user_id'])->toBe(7)
        ->and(sessionStateFor()['grace'])->toBeFalse();
});

it('does not take over a live session belonging to someone else', function (): void {
    /*
     * The same reassignment against a LIVE row, and the more dangerous half.
     * activeFor() does not compare subjects and reset() acts on the row's
     * user_id, so a row left naming user 7 while grace opened for user 9 would
     * let user 9's recovery reset user 7's password.
     */
    AuthSession::create([
        'session_binding' => revivalBinding(),
        'user_id' => 7,
        'amr' => ['password'],
    ]);

    app(GraceGuard::class)->start('host-session-1', 9);

    $state = sessionStateFor();

    expect($state['user_id'])->toBe(7)
        ->and($state['grace'])->toBeFalse();
});

it('still opens grace for a host session with no row', function (): void {
    // The ordinary path, which is most of them: an anonymous host session
    // reaching recovery for the first time.
    app(GraceGuard::class)->start('host-session-1', 7);

    expect(sessionStateFor())->toBe([
        'revoked' => false,
        'reason' => null,
        'user_id' => 7,
        'grace' => true,
    ]);
});

it('still opens grace for the same subject on a live row', function (): void {
    // A user whose session is live and who then recovers: grace opens on their
    // own row, which is the shape GraceGuard::start() was written for.
    AuthSession::create([
        'session_binding' => revivalBinding(),
        'user_id' => 7,
        'amr' => ['password'],
    ]);

    app(GraceGuard::class)->start('host-session-1', 7);

    expect(sessionStateFor()['grace'])->toBeTrue()
        ->and(sessionStateFor()['user_id'])->toBe(7);
});

it('leaves an existing revocation reason alone when grace lapses', function (): void {
    /*
     * The behaviour start() is being made consistent with, asserted here so a
     * future change cannot quietly bring the two back into disagreement from
     * the other direction.
     */
    $row = revokedSession(RevokedReason::AdminRevoked);
    $row->forceFill(['recovery_grace_expires_at' => now()->subMinute()])->save();

    app(GraceGuard::class)->expireIfLapsed('host-session-1');

    expect(sessionStateFor()['reason'])->toBe(RevokedReason::AdminRevoked->value);
});

/* ---- what the caller reports -------------------------------------------- */

function revivalRequest(string $value = 'ada@acme.example'): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function revivalAccount(int $userId = 7): void
{
    AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => 'old-password']);
}

function revivalCode(): string
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    app(CredentialRecovery::class)->request(revivalRequest());

    foreach (DB::table('auth_recovery_proof_outbox')->whereNull('delivered_at')->pluck('opaque_id') as $opaqueId) {
        app(RecoveryProofOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

it('refuses the redemption rather than claiming grace opened', function (): void {
    /*
     * redeem() reported GraceOpened unconditionally after calling start(). With
     * start() now declining, that would be a lie the caller acts on -- the
     * controller redirects into a grace flow that has no capability behind it.
     */
    revivalAccount();
    $code = revivalCode();
    revokedSession(RevokedReason::PasswordChanged);

    expect(app(CredentialRecovery::class)->redeem(revivalRequest(), $code, 'host-session-1'))
        ->toBe(CredentialRecoveryOutcome::Refused)
        ->and(sessionStateFor()['grace'])->toBeFalse();
});

it('does not spend the recovery code on a refusal it cannot act on', function (): void {
    /*
     * The proof is consumed BEFORE grace is opened, so a refusal that left it
     * consumed would burn the user's one code for nothing -- and they would
     * have to request another to get anywhere. The code has to survive a
     * refusal the user could not have avoided.
     */
    revivalAccount();
    $code = revivalCode();
    revokedSession(RevokedReason::PasswordChanged);

    app(CredentialRecovery::class)->redeem(revivalRequest(), $code, 'host-session-1');

    expect(AuthRecoveryProof::query()->whereNull('consumed_at')->count())->toBe(1);
});
