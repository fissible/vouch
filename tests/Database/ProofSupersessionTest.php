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

it('leaves the previous recovery code live when hashing a new one fails', function (): void {
    /*
     * Named for what it actually covers. Hash::make() runs inside the issuance
     * transaction today, but PHP evaluates it BEFORE the insert it is an
     * argument to, and an implementation may legitimately hash before opening
     * the transaction at all -- so this shows a failed issuance leaving the
     * user's working code alone, NOT that supersession and creation commit
     * atomically. Proving that needs a fault injected after the writes, which
     * has no seam here yet and is recorded as a gap rather than claimed.
     *
     * It still earns its place: a failure here must not retire the code the
     * user is holding, or a failed retry locks them out of their own account.
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

it('leaves a decoy ceremony in the same row states as a real one', function (): void {
    /*
     * Decoys exist so an unknown identifier costs the same work as a known one.
     * If supersession ran only for real identifiers, a second request would do
     * an UPDATE for accounts that exist and none for those that do not, which
     * reintroduces the enumeration signal the decoy was built to remove.
     *
     * Requested through request() rather than the delivering helper, and this
     * is not a shortcut: the worker deletes the decoy's OUTBOX row before
     * provider I/O, so no code is ever delivered for one, though the proof row
     * itself remains and is still subject to supersession. Asking for a code
     * here would fail on the decoy side for a reason unrelated to supersession.
     *
     * What this proves is STATE parity: the same rows in the same states either
     * way. It does not prove equal WORK -- a real identifier may still cost
     * extra queries, a lock, or a retry -- and it proves nothing about latency,
     * which is the shape the enumeration threat actually takes. Equal-work
     * instrumentation is a gap, recorded rather than implied.
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


it('keeps a superseded recovery code dead once the newer proof row is gone', function (): void {
    /*
     * The escape that survives every other test here.
     *
     * An implementation can write supersession markers faithfully and still
     * enforce nothing, by selecting the newest row OVERALL -- consumed ones
     * included -- and refusing when that row is spent. Every assertion above
     * passes, because the newest row is always present to refuse on its behalf.
     * Delete it, as any retention pass eventually will, and the older proof
     * becomes newest again and redeems.
     *
     * So this is the test that asks whether redemption honours supersession
     * ITSELF, rather than inferring it from a neighbour that happens to exist.
     */
    supersessionAccount();

    $first = nextRecoveryCode();
    $second = nextRecoveryCode();

    expect(redeemRecovery($second, 'host-a'))->toBe(CredentialRecoveryOutcome::GraceOpened);

    // Reclaim the newer row. Nothing prunes these tables today, which is why
    // this is written as a deletion rather than as a call to a pruner: the
    // enforcement has to survive the row's absence whenever that arrives.
    DB::table('auth_recovery_proofs')->whereNotNull('consumed_at')->delete();

    expect(redeemRecovery($first, 'host-b'))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(supersessionGraceIsOpen('host-b'))->toBeFalse();
});

it('supersedes proofs that were already live before it, not just the previous one', function (): void {
    /*
     * Supersession by induction -- each issuance retiring only its immediate
     * predecessor -- is correct for rows this code created, and wrong for every
     * row that predates it. Rows written before the change ship live and
     * unsuperseded, so an implementation that walks back one step leaves the
     * whole existing stack redeemable after deployment.
     *
     * Seeded directly, because that is the only way to produce the state a
     * migration inherits: several simultaneously live proofs, none superseded.
     */
    supersessionAccount();

    foreach (['111111', '222222'] as $code) {
        DB::table('auth_recovery_proofs')->insert([
            'identifier_type' => 'email',
            'identifier_value' => 'ada@acme.example',
            'code_hash' => Hash::make($code),
            'is_decoy' => false,
            'expires_at' => now()->addMinutes(30),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    // Both are live before the new issuance, or this proves nothing.
    expect(liveProofCount('auth_recovery_proofs'))->toBe(2);

    $newest = nextRecoveryCode();

    /*
     * Immediately, before anything is consumed. Refusing the old codes while
     * the newest is still unconsumed only shows that the newest sorts first --
     * an implementation retiring one predecessor passes that. One live proof
     * here is the claim that the whole inherited stack is actually dead.
     */
    expect(liveProofCount('auth_recovery_proofs'))->toBe(1);

    expect(redeemRecovery($newest, 'host-c'))->toBe(CredentialRecoveryOutcome::GraceOpened);

    // And again with the newest spent, which is when a merely-preferred
    // ordering hands the stack back.
    expect(redeemRecovery('111111', 'host-a'))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(redeemRecovery('222222', 'host-b'))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(supersessionGraceIsOpen('host-a'))->toBeFalse()
        ->and(supersessionGraceIsOpen('host-b'))->toBeFalse();
});

it('keeps a superseded recovery code dead after the newer one expires', function (): void {
    /*
     * Supersession outlives the proof that caused it. If the newer code is
     * never used and simply expires, the older one must NOT quietly become the
     * best remaining candidate -- otherwise every superseded code returns to
     * life on a timer, which is the stacking defect with a delay in front.
     */
    supersessionAccount();

    $first = nextRecoveryCode();
    nextRecoveryCode();

    $newest = DB::table('auth_recovery_proofs')->orderByDesc('id')->value('id');
    shiftDeadlineOnDatabaseClock('auth_recovery_proofs', (int) stringValue($newest), -60);

    expect(redeemRecovery($first))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(supersessionGraceIsOpen('host-session-1'))->toBeFalse();
});

it('refuses the superseded code and still redeems the newest one', function (): void {
    // The combined sequence, in one test. Separate tests establish each half
    // against a fresh database; only this one shows that refusing the older
    // code leaves the newer one usable rather than burning the whole ceremony.
    supersessionAccount();

    $first = nextRecoveryCode();
    $second = nextRecoveryCode();

    expect(redeemRecovery($first, 'host-a'))->toBe(CredentialRecoveryOutcome::Refused)
        ->and(redeemRecovery($second, 'host-b'))->toBe(CredentialRecoveryOutcome::GraceOpened)
        ->and(supersessionGraceIsOpen('host-b'))->toBeTrue();
});

it('supersedes per identifier, not per user', function (): void {
    /*
     * The existing scope tests vary the identifier AND the user together, so
     * they cannot tell per-identifier supersession from per-user. One user with
     * two verified addresses separates them: recovering through one address
     * must not kill the live code sent to the other.
     */
    supersessionAccount('ada@acme.example', 1);

    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada+alt@acme.example',
        'verified_at' => now(),
    ]);

    $primary = nextRecoveryCode('ada@acme.example');
    nextRecoveryCode('ada+alt@acme.example');

    expect(app(CredentialRecovery::class)->redeem(supersessionRecoveryFor('ada@acme.example'), $primary, 'host-a'))
        ->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('supersedes within a ceremony, not across ceremonies', function (): void {
    /*
     * Recovery and verification are separate authorities by design -- a
     * verification code attests control, a recovery proof opens a password
     * reset -- so issuing one must not retire the other. An implementation that
     * superseded "every live proof for this identifier" across both tables
     * would let anyone cancel a pending verification by requesting a recovery.
     */
    supersessionAccount('grace@acme.example', 1);

    $verification = nextVerificationCode('grace@acme.example');
    nextRecoveryCode('grace@acme.example');

    expect(app(IdentifierVerifier::class)->redeem(supersessionVerificationFor('grace@acme.example'), $verification))
        ->toBe(IdentifierVerificationOutcome::Verified);
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

it('keeps a superseded verification code dead once the newer proof row is gone', function (): void {
    /*
     * The recovery half of this escape is covered above; verification needs its
     * own, because the two ceremonies are separate implementations and a marker
     * written but never consulted looks identical in both until the newer row
     * disappears.
     */
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);

    $first = nextVerificationCode();
    $second = nextVerificationCode();

    expect(redeemVerification($second))->toBe(IdentifierVerificationOutcome::Verified);

    DB::table('auth_identifier_verifications')->whereNotNull('consumed_at')->delete();

    // Cleared so a second verification would be visible rather than masked by
    // the first: otherwise "already verified" and "verified again" look alike.
    AuthIdentifier::query()->where('value', 'grace@acme.example')->update(['verified_at' => null]);

    expect(redeemVerification($first))->toBe(IdentifierVerificationOutcome::Refused)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->toBeNull();
});

it('supersedes verification proofs that were already live before it', function (): void {
    // The migration case for the other ceremony: rows that shipped live and
    // unsuperseded must not survive the first issuance after deployment.
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);

    foreach (['333333', '444444'] as $code) {
        DB::table('auth_identifier_verifications')->insert([
            'identifier_type' => 'email',
            'identifier_value' => 'grace@acme.example',
            'code_hash' => Hash::make($code),
            'is_decoy' => false,
            'expires_at' => now()->addMinutes(30),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    expect(liveProofCount('auth_identifier_verifications'))->toBe(2);

    nextVerificationCode();

    expect(liveProofCount('auth_identifier_verifications'))->toBe(1)
        ->and(redeemVerification('333333'))->toBe(IdentifierVerificationOutcome::Refused)
        ->and(redeemVerification('444444'))->toBe(IdentifierVerificationOutcome::Refused);
});

it('supersedes verification per identifier, not per user', function (): void {
    /*
     * The mirror of recovery's same-user scope test, and it is not redundant:
     * the ceremonies are separate implementations, and a mutant superseding
     * every address belonging to the owner passed the whole suite while
     * stranding the code sent to the other address.
     *
     * One user, two addresses. Verifying control of one must not cancel a
     * verification already in flight for the other.
     */
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace+alt@acme.example', 'verified_at' => null]);

    $primary = nextVerificationCode('grace@acme.example');
    nextVerificationCode('grace+alt@acme.example');

    expect(app(IdentifierVerifier::class)->redeem(supersessionVerificationFor('grace@acme.example'), $primary))
        ->toBe(IdentifierVerificationOutcome::Verified)
        ->and(AuthIdentifier::query()->where('value', 'grace@acme.example')->value('verified_at'))->not->toBeNull();
});

/**
 * Fail the first statement matching $fragment, after letting it be observed.
 *
 * A test-only seam through the connection, so no production hook exists purely
 * to be interrupted. Records what ran before the failure, which is how the
 * caller knows the interruption landed AFTER the writes it cares about rather
 * than before them.
 *
 * @param  list<string>  $seen
 */
function failAfterObserving(string $fragment, array &$seen): void
{
    $tripped = false;

    DB::connection()->beforeExecuting(function (string $query) use ($fragment, &$seen, &$tripped): void {
        $seen[] = $query;

        if (! $tripped && str_contains($query, $fragment)) {
            $tripped = true;

            throw new RuntimeException('Interrupted after the writes under test.');
        }
    });
}

it('restores the previous recovery code when issuance fails after superseding it', function (): void {
    /*
     * Atomicity, properly. The hashing test above only shows a failure BEFORE
     * anything was written; this one interrupts the outbox insert, by which
     * point supersession has run and the replacement proof exists.
     *
     * An implementation that supersedes outside the insertion transaction
     * leaves the user holding a dead code and never delivers its replacement --
     * locked out of their own account by a failed retry, which is precisely
     * what "atomically" in the contract is there to prevent.
     */
    supersessionAccount();

    $first = nextRecoveryCode();

    $seen = [];
    failAfterObserving('auth_recovery_proof_outbox', $seen);

    try {
        app(CredentialRecovery::class)->request(supersessionRecoveryFor('ada@acme.example'));
        $threw = false;
    } catch (Throwable) {
        $threw = true;
    }

    // The interruption landed where this test needs it: after a write to the
    // proofs table, not before the transaction had done anything.
    expect($threw)->toBeTrue()
        ->and(array_filter($seen, static fn (string $q): bool => str_contains($q, 'auth_recovery_proofs')))
        ->not->toBe([]);

    expect(redeemRecovery($first))->toBe(CredentialRecoveryOutcome::GraceOpened)
        ->and(supersessionGraceIsOpen('host-session-1'))->toBeTrue();
});

it('restores the previous verification code when issuance fails after superseding it', function (): void {
    // The same seam in the other ceremony, which is a separate implementation.
    AuthIdentifier::create(['user_id' => 1, 'type' => 'email', 'value' => 'grace@acme.example', 'verified_at' => null]);

    $first = nextVerificationCode();

    $seen = [];
    failAfterObserving('auth_identifier_verification_outbox', $seen);

    try {
        app(IdentifierVerifier::class)->request(supersessionVerificationFor('grace@acme.example'));
        $threw = false;
    } catch (Throwable) {
        $threw = true;
    }

    expect($threw)->toBeTrue()
        ->and(array_filter($seen, static fn (string $q): bool => str_contains($q, 'auth_identifier_verifications')))
        ->not->toBe([]);

    expect(redeemVerification($first))->toBe(IdentifierVerificationOutcome::Verified);
});
