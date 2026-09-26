<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryOutcome;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Recovery\RecoveryProofOutboxDelivery;
use Fissible\Vouch\Verification\IdentifierVerificationOutcome;
use Fissible\Vouch\Verification\IdentifierVerificationRequest;
use Fissible\Vouch\Verification\IdentifierVerifier;
use Fissible\Vouch\Verification\VerificationOutboxDelivery;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * #59. Who decides that two identifiers are the same identifier.
 *
 * Until now the database did, differently per engine. MySQL's default
 * utf8mb4_0900_ai_ci equates jose@ with a stored jose-with-acute@, so on that
 * engine they share a proof supersession scope and the auth_identifiers unique
 * constraint treats them as one address; SQLite and PostgreSQL keep them apart.
 * The same application, deployed twice, disagreed about who someone is.
 *
 * The direction of the error is not uniform, which is the argument for deciding
 * it once rather than per call site. Coarser equality lets one person's request
 * invalidate another's proof. Finer equality treats a request the database
 * considers a repeat as new. Neither is safe to leave to a deployment's
 * collation.
 *
 * So identity becomes IdentifierCanonicalizer's, and the columns stop having an
 * opinion: a deterministic collation makes SQL equality byte equality, and the
 * canonical form is what gets stored and what gets compared.
 *
 * That pairing is the whole change, and half of it alone would be a regression.
 * Byte equality WITHOUT canonicalizing on write and on lookup would stop MySQL
 * matching Ada@ to ada@, which it matches today. Canonicalizing without the
 * collation would leave the engine free to equate more than the canonical form
 * does.
 *
 * IdentifierCanonicalizer already exists and already means this -- ThrottleKey
 * has canonicalized subjects since throttling was written. #59 stops that being
 * the only place identity is defined.
 */

function permitIdentifierDelivery(): void
{
    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());
}

function storedIdentifier(string $value, int $userId = 1): AuthIdentifier
{
    return AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => $value,
        'verified_at' => now(),
    ]);
}

function requestRecoveryAs(string $submitted): void
{
    DB::table('auth_throttle_counters')->delete();
    DB::table('auth_throttle_tuples')->delete();

    app(CredentialRecovery::class)->request(new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: $submitted,
        tenantId: null,
        clientIp: '203.0.113.10',
    ));
}

function requestVerificationAs(string $submitted): void
{
    DB::table('auth_throttle_counters')->delete();
    DB::table('auth_throttle_tuples')->delete();

    app(IdentifierVerifier::class)->request(new IdentifierVerificationRequest(
        type: 'email',
        submittedIdentifier: $submitted,
        tenantId: null,
        clientIp: '203.0.113.10',
    ));
}


it('stores the canonical form rather than what was submitted', function (): void {
    /*
     * The write side. Storing the submitted spelling leaves two rows for one
     * address as soon as someone capitalises differently, and the unique
     * constraint cannot see that they are the same.
     */
    $identifier = storedIdentifier('Ada@Acme.Example');

    expect(DB::table('auth_identifiers')->where('id', $identifier->id)->value('value'))
        ->toBe('ada@acme.example');
});

it('resolves a submitted spelling to the stored canonical one', function (): void {
    permitIdentifierDelivery();
    storedIdentifier('ada@acme.example');

    /*
     * The read side, and the half that would regress without it. With byte
     * equality and no canonicalization at lookup, a user who types their
     * address with a capital stops being recognised on MySQL, where they are
     * recognised today.
     */
    requestRecoveryAs('ADA@Acme.Example');

    expect(DB::table('auth_recovery_proofs')
        ->where('identifier_value', canonical('ada@acme.example'))
        ->where('is_decoy', false)->count())->toBe(1);
});

it('treats a decomposed spelling as the same identifier', function (): void {
    permitIdentifierDelivery();
    storedIdentifier("jos\u{e9}@acme.example");

    // Normalization is part of the canonical form, so the two encodings of one
    // address are one address on every engine rather than on none.
    requestRecoveryAs("jose\u{301}@acme.example");

    expect(DB::table('auth_recovery_proofs')->where('is_decoy', false)->count())->toBe(1);
});

it('keeps an accented address distinct from its unaccented spelling', function (): void {
    permitIdentifierDelivery();
    storedIdentifier("jos\u{e9}@acme.example", 1);

    /*
     * The case this issue exists for. MySQL's default collation equates these
     * two, so a recovery request for one resolves the other's identifier and
     * can open grace against an account the requester does not control. They
     * are different addresses and must resolve differently on every engine.
     */
    requestRecoveryAs('jose@acme.example');

    $proofs = DB::table('auth_recovery_proofs')->get();

    expect($proofs)->toHaveCount(1)
        ->and(requiredRow($proofs->first())->is_decoy)->toBeTruthy();
});

it('gives every identifier column a deterministic collation', function (): void {
    $driver = DB::connection()->getDriverName();

    if ($driver === 'sqlite') {
        $this->markTestSkipped('SQLite compares text as bytes unless a column asks otherwise.');
    }

    /*
     * Asked of the schema, not assumed from a migration's source. A column left
     * on an accent-insensitive collation keeps its own opinion about identity
     * however carefully the application canonicalizes on the way in.
     */
    foreach (identifierColumns() as [$table, $column]) {
        expect(carriesDeterministicCollation($table, $column))->toBeTrue(sprintf('%s.%s must compare deterministically', $table, $column));
    }
});



it('supersedes within one identity and not across two', function (): void {
    permitIdentifierDelivery();
    storedIdentifier('ada@acme.example', 1);
    storedIdentifier("jos\u{e9}@acme.example", 2);

    /*
     * Supersession scopes on identifier_value, so the identity decision reaches
     * it directly: differently-spelled submissions for ONE address must
     * supersede each other, and two different addresses must not.
     */
    requestRecoveryAs('ada@acme.example');
    requestRecoveryAs('ADA@ACME.EXAMPLE');
    requestRecoveryAs("jos\u{e9}@acme.example");

    $ada = DB::table('auth_recovery_proofs')->where('identifier_value', 'ada@acme.example');
    $jose = DB::table('auth_recovery_proofs')
        ->where('identifier_value', canonical("jos\u{e9}@acme.example"));

    expect((clone $ada)->whereNotNull('superseded_at')->count())->toBe(1)
        ->and((clone $ada)->whereNull('superseded_at')->count())->toBe(1)
        ->and((clone $jose)->whereNull('superseded_at')->count())->toBe(1)
        ->and((clone $jose)->whereNotNull('superseded_at')->count())->toBe(0);
});

/** Issue a recovery proof and return the delivered code. */
function deliveredRecoveryCode(string $submitted): string
{
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    requestRecoveryAs($submitted);

    foreach (DB::table('auth_recovery_proof_outbox')->pluck('opaque_id') as $opaqueId) {
        app(RecoveryProofOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    return $delivery->lastCode();
}

it('redeems a proof through a differently spelled submission', function (): void {
    storedIdentifier('ada@acme.example');
    $code = deliveredRecoveryCode('ada@acme.example');

    /*
     * redeem(), not only request(). An implementation canonicalizing on issue
     * and not on redemption hands a user a code they can never spend -- it
     * survived the entire suite when measured, because nothing exercised the
     * redemption path for identity at all.
     */
    expect(app(CredentialRecovery::class)->redeem(
        new CredentialRecoveryRequest(
            type: 'email',
            submittedIdentifier: 'ADA@Acme.Example',
            tenantId: null,
            clientIp: '203.0.113.10',
        ),
        $code,
        'host-session-1',
    ))->toBe(CredentialRecoveryOutcome::GraceOpened);
});

it('verifies an identifier through a differently spelled submission', function (): void {
    $delivery = new ArrayOtpDelivery();
    app()->instance(OtpDelivery::class, $delivery);
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    $identifier = AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => null,
    ]);

    /*
     * The verification ceremony, which #59 names explicitly and which nothing
     * else here touched. An implementation canonicalizing recovery and not
     * verification survived 2,327 tests.
     */
    app(IdentifierVerifier::class)->request(new IdentifierVerificationRequest(
        type: 'email',
        submittedIdentifier: 'ada@acme.example',
        tenantId: null,
        clientIp: '203.0.113.10',
    ));

    foreach (DB::table('auth_identifier_verification_outbox')->pluck('opaque_id') as $opaqueId) {
        app(VerificationOutboxDelivery::class)->deliver(stringValue($opaqueId));
    }

    $outcome = app(IdentifierVerifier::class)->redeem(
        new IdentifierVerificationRequest(
            type: 'email',
            submittedIdentifier: 'Ada@ACME.example',
            tenantId: null,
            clientIp: '203.0.113.10',
        ),
        $delivery->lastCode(),
    );

    expect($outcome)->toBe(IdentifierVerificationOutcome::Verified)
        ->and($identifier->refresh()->verified_at)->not->toBeNull();
});

it('resolves an uppercase accented spelling', function (): void {
    permitIdentifierDelivery();
    storedIdentifier("jos\u{e9}@acme.example");

    /*
     * Case folding that reaches non-ASCII, which every other case here left
     * open: NFC plus a byte-wise strtolower() leaves an accented capital in its
     * own bucket and was otherwise indistinguishable from correct.
     */
    requestRecoveryAs("JOS\u{c9}@ACME.EXAMPLE");

    expect(DB::table('auth_recovery_proofs')
        ->where('identifier_value', canonical("jos\u{e9}@acme.example"))
        ->where('is_decoy', false)->count())->toBe(1);
});

it('keeps one value string apart across two identifier types', function (): void {
    permitIdentifierDelivery();

    /*
     * The type is half the scope. Dropping it from the supersession predicate
     * leaves an email and a phone number that happen to spell the same string
     * sharing one scope, so issuing for one supersedes the other -- and it
     * survived everything, because nothing here used two types.
     */
    requestRecoveryAs('shared-spelling');
    app(CredentialRecovery::class)->request(new CredentialRecoveryRequest(
        type: 'sms',
        submittedIdentifier: 'shared-spelling',
        tenantId: null,
        clientIp: '203.0.113.10',
    ));

    $live = DB::table('auth_recovery_proofs')
        ->where('identifier_value', 'shared-spelling')
        ->whereNull('superseded_at')->get();

    expect($live)->toHaveCount(2)
        ->and($live->pluck('identifier_type')->sort()->values()->all())
        ->toBe(['email', 'sms']);
});

/** A derived binding, which is what FlowRequest takes -- never a raw session id. */
function identifierFlowBinding(string $seed): string
{
    return str_repeat($seed, 64);
}

/**
 * Begin a flow and return its handle.
 *
 * Narrowed to the continuing result rather than annotated onto FlowResult, which
 * is a marker interface: not every implementation of it carries a handle, so a
 * docblock claiming one would assert something false about the others.
 */
function beginIdentifierFlow(string $seed): string
{
    $begun = app(AuthFlow::class)->advance(
        new FlowRequest(null, 'begin', [], identifierFlowBinding($seed)),
    );

    if (! $begun instanceof Continuing || $begun->handle === null) {
        throw new RuntimeException('The flow did not begin with a continuing handle.');
    }

    return $begun->handle;
}

it('resolves a differently spelled identifier at the identify step', function (): void {
    /*
     * The login path, and the regression this file's header names: byte equality
     * WITHOUT canonicalizing the lookup stops MySQL matching Ada@ to ada@, which
     * it matches today. Every other test here drives recovery or verification,
     * and those ceremonies canonicalize their own request objects -- so none of
     * them says anything about identify, which resolves the identifier itself.
     */
    storedIdentifier('ada@acme.example');

    $known = beginIdentifierFlow('i');

    app(AuthFlow::class)->advance(new FlowRequest(
        $known,
        'submit',
        ['identifier' => 'ADA@Acme.Example'],
        identifierFlowBinding('i'),
    ));

    /*
     * A second flow submitting an address nobody holds, because a recorded
     * user_id is only evidence that the lookup RESOLVED if it can also come back
     * null. Without this control an implementation that stamped the attempt
     * unconditionally would satisfy the assertion above.
     */
    $unknown = beginIdentifierFlow('j');

    app(AuthFlow::class)->advance(new FlowRequest(
        $unknown,
        'submit',
        ['identifier' => 'ZOE@Acme.Example'],
        identifierFlowBinding('j'),
    ));

    expect(AuthAttempt::query()->where('handle', $known)->value('user_id'))->toBe(1)
        ->and(AuthAttempt::query()->where('handle', $unknown)->value('user_id'))->toBeNull();
});

/*
 * #63. A deterministic collation is not the same thing as a NO PAD one.
 *
 * #59 installed utf8mb4_bin on MySQL, which is PAD SPACE: a query for
 * 'ada@x ' matches a stored 'ada@x', and unique(type, value) rejects the second
 * spelling as a duplicate. PostgreSQL's C and SQLite's BINARY do neither, so
 * trailing ASCII whitespace remained exactly the kind of engine-dependent
 * equality the collation was installed to end -- and the assertion guarding it
 * asked for a name ending in '_bin', which the padding collation satisfies.
 *
 * Reachable rather than theoretical: IdentifierCanonicalizer normalizes case and
 * Unicode but does not trim, so the space survives into the stored value and
 * into the lookup parameter, and the engine decides.
 *
 * These assert the BEHAVIOUR, on every engine and with no skips, because the
 * property at issue is that the three engines agree. Whether a trailing space
 * ought to be trimmed is a separate question about identity policy; what is
 * settled here is that the answer cannot depend on which database is installed.
 */

it('treats a trailing space as a different identifier', function (): void {
    /*
     * Two rows, everywhere. On a PAD SPACE collation the second create violates
     * unique(type, value) instead, so this fails by exception rather than by
     * count on the engine that has the defect -- which is why the count is
     * asserted after both writes rather than between them.
     */
    storedIdentifier('ada@acme.example');
    storedIdentifier('ada@acme.example ', 2);

    expect(AuthIdentifier::query()->count())->toBe(2)
        ->and(AuthIdentifier::query()->where('value', 'ada@acme.example')->count())->toBe(1)
        ->and(AuthIdentifier::query()->where('value', 'ada@acme.example')->value('user_id'))->toBe(1)
        ->and(AuthIdentifier::query()->where('value', 'ada@acme.example ')->value('user_id'))->toBe(2);
});

it('does not resolve a padded submission onto an unpadded identifier', function (): void {
    /*
     * The consequence that matters. A submission with a trailing space reaching
     * someone else's identifier is an account-takeover shape on one engine and
     * nothing at all on the other two.
     */
    storedIdentifier('ada@acme.example');

    expect(AuthIdentifier::query()->where('value', 'ada@acme.example ')->exists())->toBeFalse()
        ->and(AuthIdentifier::query()->where('value', canonical('ada@acme.example '))->exists())->toBeFalse()
        /*
         * The positive control. Two absences prove nothing on their own -- a
         * lookup that had stopped finding anything at all would satisfy both.
         */
        ->and(AuthIdentifier::query()->where('value', 'ada@acme.example')->exists())->toBeTrue();
});

it('keeps padded and unpadded spellings in separate issuance scopes', function (string $ceremony): void {
    permitIdentifierDelivery();

    /*
     * The proof tables carry no unique index, so a padding collation does not
     * fail here -- it silently shares. insertOrIgnore sees the padded spelling as
     * a duplicate of the stored one and the ceremony locks the row already there,
     * so two identifiers share one mutex and one supersession scope. Counted
     * rather than inspected, because sharing is invisible in any single row.
     */
    foreach (['ada@acme.example', 'ada@acme.example '] as $value) {
        if ($ceremony === 'recovery') {
            requestRecoveryAs($value);
        } else {
            requestVerificationAs($value);
        }
    }

    expect(DB::table('auth_proof_issuance_locks')->count())->toBe(2)
        ->and(DB::table('auth_proof_issuance_locks')->distinct()->count('identifier_value'))->toBe(2);
})->with(['recovery', 'verification']);

it('carries a collation that pads nothing on every identifier column', function (): void {
    /*
     * The schema half, and the assertion whose weakness let this ship: a name
     * ending in '_bin' does not mean NO PAD. Pinned so a later migration cannot
     * return to a padding collation while still satisfying the name check.
     *
     * A MySQL assertion in practice, and deliberately not skipped elsewhere:
     * comparesWithoutPadding() is true by construction off MySQL, because
     * PostgreSQL does not pad varchar comparisons and SQLite compares bytes.
     * Running it everywhere keeps the contract stated in one place; the engine
     * that can fail it is MySQL, and the control that proves it CAN fail lives in
     * NoPadCollationMigrationTest.
     */
    foreach (identifierColumns() as [$table, $column]) {
        expect(comparesWithoutPadding($table, $column))
            ->toBeTrue(sprintf('%s.%s must compare without padding', $table, $column));
    }
});
