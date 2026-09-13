<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryOutcome;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Tests\Support\ThrowingHasher;
use Fissible\Vouch\Verification\IdentifierVerificationOutcome;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/*
 * Issue #38 -- issuing a code permanently invalidates every earlier one.
 *
 * Both redeem paths selected the newest UNCONSUMED proof. That produced two
 * defects at once, and the second is the serious one:
 *
 *   - STRANDING. A user who requested a second code before using the first
 *     found the first silently unusable: not expired, not consumed, not
 *     matched, simply never the row the query returned. The delivered code and
 *     the accepted code differed with no signal.
 *
 *   - CAPABILITY STACKING. Consuming the newest did not retire the earlier one,
 *     it PROMOTED it: the older proof became newest-unconsumed and was usable
 *     again. Each redemption opens grace, which is a password-reset capability,
 *     so N requests accumulated N resets rather than replacing one another.
 *
 * The frozen invariant: for each subject and purpose -- and identifier, where
 * the ceremony is identifier-specific -- issuing a new code permanently
 * invalidates every prior unconsumed proof.
 *
 * PERMANENTLY is the load-bearing word, and it is why these tests redeem the
 * newest code and then try the older one again. An implementation that merely
 * prefers the newest passes every test that stops before that second attempt,
 * while leaving the stack intact underneath.
 *
 * Supersession is recorded separately from consumption. A superseded proof was
 * never redeemed, so marking it consumed would file a reset that never happened
 * -- and the attempt accounting in #31 would inherit budgets it cannot explain.
 * It also has to be checkable on its own, before expiry or consumption, which a
 * reused column cannot express.
 */

function supersessionRecoveryFor(string $value): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function supersessionVerificationFor(string $value): IdentifierVerificationRequest
{
    return new IdentifierVerificationRequest(
        type: 'email',
        submittedIdentifier: $value,
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

/** A verified identifier with a password credential, ready to recover. */
function supersessionAccount(string $value = 'ada@acme.example', int $userId = 1): void
{
    AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => 'old-password']);
}

function supersessionBindDelivery(): ArrayOtpDelivery
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    return $delivery;
}

/**
 * Request one recovery code and return THAT issuance's code.
 *
 * Only undelivered outbox rows are worked, so calling this repeatedly yields
 * each new code rather than redelivering the first. A helper that returned "the
 * last code" regardless would make every supersession test here compare a code
 * against itself.
 */
function nextRecoveryCode(string $value = 'ada@acme.example'): string
{
    $delivery = supersessionBindDelivery();

    app(CredentialRecovery::class)->request(supersessionRecoveryFor($value));

    foreach (DB::table('auth_recovery_proof_outbox')->whereNull('delivered_at')->pluck('opaque_id') as $opaqueId) {
        app(RecoveryProofOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

function nextVerificationCode(string $value = 'grace@acme.example'): string
{
    $delivery = supersessionBindDelivery();

    app(IdentifierVerifier::class)->request(supersessionVerificationFor($value));

    foreach (DB::table('auth_identifier_verification_outbox')->whereNull('delivered_at')->pluck('opaque_id') as $opaqueId) {
        app(VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

function redeemRecovery(string $code, string $host = 'host-session-1'): CredentialRecoveryOutcome
{
    return app(CredentialRecovery::class)->redeem(supersessionRecoveryFor('ada@acme.example'), $code, $host);
}

function redeemVerification(string $code): IdentifierVerificationOutcome
{
    return app(IdentifierVerifier::class)->redeem(supersessionVerificationFor('grace@acme.example'), $code);
}

/**
 * Rows that could still be redeemed: unconsumed, unsuperseded, unexpired.
 *
 * The column check is not defensive noise. SQLite resolves a double-quoted
 * identifier it does not recognise as a STRING LITERAL, so `whereNull` on a
 * missing column matches nothing and silently returns 0 -- a count that reads
 * like "no live proofs" and would let this fixture pass against an
 * implementation that never built the column at all. MySQL and PostgreSQL
 * would error on the same query, so the vacancy is engine-specific too.
 */
function liveProofCount(string $table): int
{
    foreach (['consumed_at', 'superseded_at'] as $column) {
        if (! Schema::hasColumn($table, $column)) {
            throw new RuntimeException(
                "auth proofs have no {$column} column, so this count cannot mean what it says.",
            );
        }
    }

    return DB::table($table)
        ->whereNull('consumed_at')
        ->whereNull('superseded_at')
        ->whereRaw('expires_at > CURRENT_TIMESTAMP')
        ->count();
}

function supersessionGraceIsOpen(string $host): bool
{
    return app(GraceGuard::class)->activeFor($host) instanceof AuthSession;
}

/* ---- recovery ----------------------------------------------------------- */

it('refuses a recovery code superseded by a later request', function (): void {
    // Stranding, stated as a refusal rather than a silence. The user submits
    // exactly what was delivered to them, and the ceremony must not accept it.
    supersessionAccount();

    $first = nextRecoveryCode();
    $second = nextRecoveryCode();

    expect($first)->not->toBe($second);

    expect(redeemRecovery($first))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(supersessionGraceIsOpen('host-session-1'))->toBeFalse();
});

it('redeems the newest recovery code', function (): void {
    // The control. Without it, "refuses the first" could equally be an
    // implementation that refuses everything after a second request.
    supersessionAccount();

    nextRecoveryCode();
    $second = nextRecoveryCode();

    expect(redeemRecovery($second))->toBe(CredentialRecoveryOutcome::GraceOpened)
        ->and(supersessionGraceIsOpen('host-session-1'))->toBeTrue();
});

it('keeps a superseded recovery code dead after the newest one is consumed', function (): void {
    /*
     * The capability-stacking escape, and the reason supersession has to be
     * permanent rather than an ordering preference.
     *
     * Consuming the newest proof used to make the earlier one newest-unconsumed
     * and therefore selectable again -- so this exact sequence handed out a
     * SECOND password-reset capability from a code the user had already been
     * told to replace. An implementation that only sorts by id passes every
     * assertion above and fails here.
     */
    supersessionAccount();

    $first = nextRecoveryCode();
    $second = nextRecoveryCode();

    expect(redeemRecovery($second, 'host-a'))->toBe(CredentialRecoveryOutcome::GraceOpened);

    expect(redeemRecovery($first, 'host-b'))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(supersessionGraceIsOpen('host-b'))->toBeFalse();
});

it('supersedes every earlier recovery proof, not only the previous one', function (): void {
    // Supersession is not one deep. An implementation that retires only the
    // immediately preceding proof leaves a stack of older ones behind, which is
    // the same defect with one more request in front of it.
    supersessionAccount();

    $first = nextRecoveryCode();
    $second = nextRecoveryCode();
    $third = nextRecoveryCode();

    expect(redeemRecovery($first, 'host-a'))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(redeemRecovery($second, 'host-b'))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(redeemRecovery($third, 'host-c'))->toBe(CredentialRecoveryOutcome::GraceOpened);

    expect(liveProofCount('auth_recovery_proofs'))->toBe(0);
});

it('records a superseded recovery proof as superseded, not as consumed', function (): void {
    /*
     * State has to match behaviour. Marking a superseded proof consumed would
     * record a redemption that never happened -- #31's attempt accounting would
     * then count a reset nobody performed -- and it would leave supersession
     * unable to be checked before consumption, which the contract requires.
     */
    supersessionAccount();

    nextRecoveryCode();
    nextRecoveryCode();

    $rows = DB::table('auth_recovery_proofs')->orderBy('id')->get();

    expect($rows)->toHaveCount(2);

    $earlier = requiredRow($rows[0]);
    $newest = requiredRow($rows[1]);

    expect($earlier->superseded_at)->not->toBeNull()
        ->and($earlier->consumed_at)->toBeNull()
        ->and($newest->superseded_at)->toBeNull()
        ->and($newest->consumed_at)->toBeNull();
});

it('supersedes only the identifier the new code was issued for', function (): void {
    /*
     * Scope. A recovery for one address must not silently kill another user's
     * live code -- that would turn any stranger's request into a denial of
     * service against an account they do not control.
     */
    supersessionAccount('ada@acme.example', 1);
    supersessionAccount('bob@acme.example', 2);

    $ada = nextRecoveryCode('ada@acme.example');
    nextRecoveryCode('bob@acme.example');

    expect(app(CredentialRecovery::class)->redeem(supersessionRecoveryFor('ada@acme.example'), $ada, 'host-a'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('leaves the previous recovery code live when a new issuance fails', function (): void {
    /*
     * Atomicity. Supersession and the new proof are one unit: if the issuance
     * fails after the earlier proof was retired, the user is left holding a
     * code that no longer works and never received the one meant to replace it
     * -- locked out by a failed retry.
     */
    supersessionAccount();

    $first = nextRecoveryCode();

    $real = Hash::driver();

    if (! $real instanceof \Illuminate\Contracts\Hashing\Hasher) {
        throw new RuntimeException('Expected a hasher to wrap.');
    }

    $throwing = new ThrowingHasher($real);
    Hash::swap($throwing);

    try {
        app(CredentialRecovery::class)->request(supersessionRecoveryFor('ada@acme.example'));
        $threw = false;
    } catch (Throwable) {
        $threw = true;
    }

    Hash::swap($real);

    // The issuance really failed, and it failed where this test believes it
    // does -- otherwise the survival below would prove nothing.
    expect($threw)->toBeTrue()
        ->and($throwing->makeCalls)->toBeGreaterThan(0);

    // The point of the test: the code the user is holding still works.
    expect(redeemRecovery($first))->toBe(CredentialRecoveryOutcome::GraceOpened)
        ->and(supersessionGraceIsOpen('host-session-1'))->toBeTrue();
});

it('supersedes a decoy ceremony exactly as it supersedes a real one', function (): void {
    /*
     * Decoys exist so an unknown identifier costs the same work as a known one.
     * If supersession ran only for real identifiers, a second request would do
     * an UPDATE for accounts that exist and none for those that do not, which
     * reintroduces the enumeration signal the decoy was built to remove.
     *
     * Requested through request() rather than the delivering helper, and this
     * is not a shortcut: a decoy is deleted before provider I/O, so no code is
     * ever delivered for one. Asking for a code here would fail on the decoy
     * side for a reason that has nothing to do with supersession.
     *
     * Compared as COUNTS per state rather than by reading the decoy flag, so
     * the assertion is about work performed rather than about a column.
     */
    supersessionAccount('ada@acme.example', 1);
    supersessionBindDelivery();

    app(CredentialRecovery::class)->request(supersessionRecoveryFor('ada@acme.example'));
    app(CredentialRecovery::class)->request(supersessionRecoveryFor('ada@acme.example'));

    $real = [
        'total' => DB::table('auth_recovery_proofs')->where('is_decoy', false)->count(),
        'superseded' => DB::table('auth_recovery_proofs')->where('is_decoy', false)->whereNotNull('superseded_at')->count(),
    ];

    app(CredentialRecovery::class)->request(supersessionRecoveryFor('nobody@acme.example'));
    app(CredentialRecovery::class)->request(supersessionRecoveryFor('nobody@acme.example'));

    $decoy = [
        'total' => DB::table('auth_recovery_proofs')->where('is_decoy', true)->count(),
        'superseded' => DB::table('auth_recovery_proofs')->where('is_decoy', true)->whereNotNull('superseded_at')->count(),
    ];

    // Non-zero, or two empty tallies would match each other and prove nothing.
    expect($real['total'])->toBe(2)
        ->and($real['superseded'])->toBe(1)
        ->and($decoy)->toBe($real);
});

/* ---- identifier verification -------------------------------------------- */

it('refuses a verification code superseded by a later request', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);

    $first = nextVerificationCode();
    $second = nextVerificationCode();

    expect($first)->not->toBe($second);

    expect(redeemVerification($first))->toBe(IdentifierVerificationOutcome::Refused)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->toBeNull();
});

it('verifies with the newest verification code', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);

    nextVerificationCode();
    $second = nextVerificationCode();

    expect(redeemVerification($second))->toBe(IdentifierVerificationOutcome::Verified)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->not->toBeNull();
});

it('keeps a superseded verification code dead after the newest one is consumed', function (): void {
    /*
     * The same stacking escape in the other ceremony. It matters here because a
     * verified identifier is what recovery later accepts as a target, so a
     * second usable verification is a second way to re-verify an address the
     * user may have already lost control of.
     */
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);

    $first = nextVerificationCode();
    $second = nextVerificationCode();

    expect(redeemVerification($second))->toBe(IdentifierVerificationOutcome::Verified);

    // Clear the mark so a second success would be visible rather than masked by
    // the first: without this, "already verified" and "verified again" look the
    // same and the assertion would pass on either.
    AuthIdentifier::query()->where('value', 'grace@acme.example')->update(['verified_at' => null]);

    expect(redeemVerification($first))->toBe(IdentifierVerificationOutcome::Refused)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->toBeNull();
});

it('records a superseded verification proof as superseded, not as consumed', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);

    nextVerificationCode();
    nextVerificationCode();

    $rows = DB::table('auth_identifier_verifications')->orderBy('id')->get();

    expect($rows)->toHaveCount(2);

    $earlier = requiredRow($rows[0]);
    $newest = requiredRow($rows[1]);

    expect($earlier->superseded_at)->not->toBeNull()
        ->and($earlier->consumed_at)->toBeNull()
        ->and($newest->superseded_at)->toBeNull();
});

it('supersedes only the identifier the new verification was issued for', function (): void {
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    AuthIdentifier::create(['user_id' => 2, 'type' => 'email', 'value' => 'other@acme.example', 'verified_at' => null]);

    $grace = nextVerificationCode('grace@acme.example');
    nextVerificationCode('other@acme.example');

    expect(redeemVerification($grace))->toBe(IdentifierVerificationOutcome::Verified);
});
