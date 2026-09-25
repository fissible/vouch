<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
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

/**
 * Every column that holds an identifier value or type.
 *
 * @return list<array{string, string}>
 */
function identifierColumns(): array
{
    return [
        ['auth_identifiers', 'value'],
        ['auth_identifiers', 'type'],
        ['auth_identifier_verifications', 'identifier_value'],
        ['auth_identifier_verifications', 'identifier_type'],
        ['auth_recovery_proofs', 'identifier_value'],
        ['auth_recovery_proofs', 'identifier_type'],
        ['auth_proof_issuance_locks', 'identifier_value'],
        ['auth_proof_issuance_locks', 'identifier_type'],
    ];
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
