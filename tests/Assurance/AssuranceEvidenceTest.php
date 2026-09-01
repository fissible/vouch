<?php

declare(strict_types=1);

use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\MalformedEvidence;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tokens\SubjectKey;

/*
 * 2.4 Task 2a — the evidence value.
 *
 * AssuranceEvidence is the immutable persisted proof: the factors that were
 * actually satisfied, the subject they were satisfied for, and the tenant whose
 * policy governed them. It carries NO assurance level. A level is derived on
 * demand from the factors, so there is no cached level for authorization to
 * read, and no way for a stored level to disagree with the proof behind it.
 *
 * The serialization rules here are load-bearing rather than housekeeping.
 * Evidence is written once at login and read on every authorized request, so a
 * decoder that is lenient about a damaged row is a decoder that invents
 * assurance nobody witnessed.
 */

it('carries the persisted proof, the subject and the tenant', function (): void {
    $factors = [evidenceFactor()];
    $evidence = new AssuranceEvidence(SubjectKey::of('App\\Models\\User', 7), 'acme', $factors);

    expect($evidence->subject->render())->toBe('App\\Models\\User:7')
        ->and($evidence->tenantId)->toBe('acme')
        ->and($evidence->factors)->toBe($factors);
});

it('treats a null tenant as global rather than as unset', function (): void {
    expect(evidenceFor([evidenceFactor()], null)->tenantId)->toBeNull();
});

it('has no assurance level property for authorization to read', function (): void {
    /*
     * The addendum makes derived ACR a display and index projection, never an
     * authorization input. The strongest available form of that rule is an
     * evidence value with no level field at all: there is nothing to trust.
     *
     * Issue #10 strengthened this: the value object no longer names a level at
     * all. It exposes the derived FACTS, and whoever holds a vocabulary names
     * them. So the absent-field rule now extends to the method that used to
     * reach into the container for one.
     *
     * This is a structural assertion, and structural assertions are weak on
     * their own. The behavioural half lives in AssuranceComparisonTest and
     * AcrProjectionTest, which prove the comparator reaches the same verdict
     * for a session whose PERSISTED acr claims something the factors do not
     * support.
     */
    $evidence = evidenceFor([evidenceFactor()]);

    $shape = new ReflectionClass($evidence::class);

    expect($shape->hasProperty('acr'))->toBeFalse()
        ->and($shape->hasProperty('level'))->toBeFalse()
        ->and($shape->hasMethod('derivedAcr'))->toBeFalse()
        ->and($shape->hasMethod('facts'))->toBeTrue();
});

it('derives its level from the factors, matching the kernel', function (): void {
    // The projection must agree with AssuranceFacts, or the displayed level and
    // the enforced level are two different opinions.
    $single = evidenceFor([evidenceFactor()]);
    $multi = evidenceFor([
        evidenceFactor('password'),
        evidenceFactor('totp', '2026-08-29T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]);

    expect(nameOf($single))->toBe('aal1')
        ->and(nameOf($multi))->toBe('aal2');
});

it('anchors recency to the OLDEST factor, never the newest', function (): void {
    /*
     * The column this lands in was named last_factor_at while its migration
     * comment said "oldest satisfied factor". Written from the newest factor, a
     * fresh second factor would launder a stale first one: log in with a
     * six-week-old password plus a TOTP now, and a max_age of one hour passes.
     * Recency is governed by the stalest evidence in the proof.
     */
    $evidence = evidenceFor([
        evidenceFactor('password', '2026-07-01T10:00:00+00:00'),
        evidenceFactor('totp', '2026-08-29T10:00:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]);

    expect($evidence->weakestSatisfiedAt()->format(DATE_ATOM))->toBe('2026-07-01T10:00:00+00:00');
});

it('does not depend on the order the proof was assembled in', function (): void {
    $ordered = evidenceFor([
        evidenceFactor('password', '2026-07-01T10:00:00+00:00'),
        evidenceFactor('totp', '2026-08-29T10:00:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]);
    $reversed = evidenceFor([
        evidenceFactor('totp', '2026-08-29T10:00:00+00:00', FactorStrength::Possession, 'cred-2'),
        evidenceFactor('password', '2026-07-01T10:00:00+00:00'),
    ]);

    expect($reversed->weakestSatisfiedAt())->toEqual($ordered->weakestSatisfiedAt())
        ->and(nameOf($reversed))->toBe(nameOf($ordered));
});

it('refuses to exist with an empty proof', function (): void {
    // Evidence of nothing is not evidence. Permitting it would create a value
    // that derives aal0 and satisfies an aal0 requirement, which is a login
    // that proved nothing passing a check that asked for nothing.
    expect(fn () => evidenceFor([]))->toThrow(MalformedEvidence::class);
});

/*
 * Serialization. Every case below is a row that could genuinely be read back
 * out of auth_sessions -- truncated JSON, a factor written by an older version,
 * a hand-edited row -- and every one of them must refuse rather than degrade.
 */

it('round-trips a well-formed proof through its persisted form', function (): void {
    $evidence = evidenceFor([
        evidenceFactor('password', '2026-07-01T10:00:00+00:00'),
        evidenceFactor('totp', '2026-08-29T10:00:00+00:00', FactorStrength::Possession, 'cred-2'),
    ], 'acme');

    $restored = AssuranceEvidence::fromArray($evidence->toArray());

    expect($restored->subject->render())->toBe($evidence->subject->render())
        ->and($restored->tenantId)->toBe('acme')
        ->and(nameOf($restored))->toBe(nameOf($evidence))
        ->and($restored->weakestSatisfiedAt())->toEqual($evidence->weakestSatisfiedAt())
        ->and(array_map(static fn (SatisfiedFactor $f): string => $f->factorId, $restored->factors))
        ->toBe(['password', 'totp']);
});

it('survives the round trip losslessly, field by field', function (): void {
    // toArray()/fromArray() agreeing on the fields the comparator happens to
    // read is not a round trip. A dropped phishingResistant or authenticatorId
    // is invisible today and load-bearing the moment a policy reads it.
    $factor = new SatisfiedFactor(
        factorId: 'passkey',
        credentialId: 'cred-9',
        kind: FactorKind::Possession,
        strength: FactorStrength::Possession,
        isMultiFactor: true,
        userVerified: true,
        phishingResistant: true,
        authenticatorId: 'aaguid-1',
        satisfiedAt: new DateTimeImmutable('2026-08-29T10:00:00+00:00'),
    );

    $restored = AssuranceEvidence::fromArray(evidenceFor([$factor], 'acme')->toArray());

    expect($restored->factors[0])->toEqual($factor);
});

it('REFUSES a malformed proof rather than skipping the bad row', function (array $proof): void {
    /*
     * AuthFlow's rehydration skips unreadable evidence, because there the cost
     * of skipping is re-presenting a factor. Here the cost of skipping is
     * authorizing on a subset of the proof the user actually presented, which
     * silently lowers the derived level -- or, if the dropped factor was the
     * weakest, silently RAISES the recency. Refusal is the only safe direction.
     */
    expect(fn () => AssuranceEvidence::fromArray($proof))->toThrow(MalformedEvidence::class);
})->with(static function (): array {
    $wellFormed = [
        'factor_id' => 'password',
        'credential_id' => 'cred-1',
        'kind' => 'knowledge',
        'strength' => 'knowledge',
        'is_multi_factor' => false,
        'user_verified' => false,
        'phishing_resistant' => false,
        'authenticator_id' => null,
        'satisfied_at' => '2026-08-29T10:00:00+00:00',
    ];

    // Each case is the well-formed proof with exactly one thing wrong, so a
    // failure names the field rather than the shape.
    $with = static function (array $overrides) use ($wellFormed): array {
        return ['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => [array_merge($wellFormed, $overrides)]];
    };
    $without = static function (string $key) use ($wellFormed): array {
        $factor = $wellFormed;
        unset($factor[$key]);

        return ['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => [$factor]];
    };

    return [
        // Envelope.
        'not an object' => [['a', 'b']],
        'no subject' => [['tenant_id' => null, 'factors' => [$wellFormed]]],
        'null subject' => [['subject' => null, 'tenant_id' => null, 'factors' => [$wellFormed]]],
        'malformed subject' => [['subject' => 'no-colon-here', 'tenant_id' => null, 'factors' => [$wellFormed]]],
        'subject with empty provider' => [['subject' => ':7', 'tenant_id' => null, 'factors' => [$wellFormed]]],
        'subject with empty id' => [['subject' => 'App\\Models\\User:', 'tenant_id' => null, 'factors' => [$wellFormed]]],
        'no factors key' => [['subject' => 'App\\Models\\User:7', 'tenant_id' => null]],
        'empty factors' => [['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => []]],
        'factors not a list' => [['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => ['a' => $wellFormed]]],
        'factor is a scalar' => [['subject' => 'App\\Models\\User:7', 'tenant_id' => null, 'factors' => ['password']]],
        'tenant is not a string' => [['subject' => 'App\\Models\\User:7', 'tenant_id' => 7, 'factors' => [$wellFormed]]],
        'tenant is empty string' => [['subject' => 'App\\Models\\User:7', 'tenant_id' => '', 'factors' => [$wellFormed]]],

        // Timestamps. The promise is that a proof can never carry an
        // unanchored or ambiguous instant into a recency comparison.
        'satisfied_at missing' => [$without('satisfied_at')],
        'satisfied_at null' => [$with(['satisfied_at' => null])],
        'satisfied_at not a string' => [$with(['satisfied_at' => 1756461600])],
        'satisfied_at empty' => [$with(['satisfied_at' => ''])],
        'satisfied_at unparseable' => [$with(['satisfied_at' => 'yesterday afternoon'])],
        'satisfied_at without offset' => [$with(['satisfied_at' => '2026-08-29 10:00:00'])],
        'satisfied_at date only' => [$with(['satisfied_at' => '2026-08-29'])],

        // Canonical string keys. A numeric factor or credential id would make
        // '42' and 42 two different authenticators depending on the driver.
        'factor_id missing' => [$without('factor_id')],
        'factor_id empty' => [$with(['factor_id' => ''])],
        'factor_id not a string' => [$with(['factor_id' => 42])],
        'factor_id padded' => [$with(['factor_id' => ' password '])],
        'credential_id missing' => [$without('credential_id')],
        'credential_id empty' => [$with(['credential_id' => ''])],
        'credential_id not a string' => [$with(['credential_id' => 42])],

        // Enumerations and flags.
        'unknown strength' => [$with(['strength' => 'telepathy'])],
        /*
         * One value, one encoding. The canonical key is 'possession_weak'; the
         * case-name spelling must NOT also decode.
         *
         * Added after the implementation shipped a fallback accepting both,
         * commented as compatibility for "existing case-name-derived rows" --
         * of which there are none, since assurance_proof is created by this
         * task's own migration. It was removed, and this is what stops it
         * coming back: without a test, the widening looks harmless.
         */
        'non-canonical strength spelling' => [$with(['strength' => 'possessionweak'])],
        'canonical spelling with different case' => [$with(['strength' => 'Possession'])],
        'strength missing' => [$without('strength')],
        'unknown kind' => [$with(['kind' => 'vibes'])],
        'kind missing' => [$without('kind')],
        'non-boolean multi factor' => [$with(['is_multi_factor' => 'yes'])],
        'non-boolean user verified' => [$with(['user_verified' => 1])],
        'non-boolean phishing resistant' => [$with(['phishing_resistant' => 'true'])],
        'authenticator id not a string' => [$with(['authenticator_id' => 42])],

        // Unknown keys are refused rather than ignored: a field this version
        // does not understand may be the one a newer version used to decide.
        'unknown factor key' => [$with(['extra' => 'x'])],
    ];
});

it('REFUSES when the damaged factor is the one carrying the level', function (): void {
    /*
     * The dangerous shape is not a wholly corrupt row -- it is a row where one
     * factor is unreadable and the rest parse cleanly. A decoder that drops the
     * bad entry here turns a genuine aal2 session into a working aal1 session,
     * which is a silent downgrade the user never sees and the audit log records
     * as an ordinary request.
     */
    $good = evidenceFor([evidenceFactor(), evidenceFactor('totp', '2026-08-29T10:05:00+00:00', FactorStrength::Possession, 'cred-2')]);
    $payload = $good->toArray();
    expect($payload['factors'][1]['strength'])->toBe('possession');

    $payload['factors'][1]['strength'] = 'telepathy';

    expect(fn () => AssuranceEvidence::fromArray($payload))->toThrow(MalformedEvidence::class);
});

it('refuses a timestamp with no timezone, rather than assuming one', function (): void {
    /*
     * A timezone-less timestamp is resolved against date.timezone, so the same
     * row would be fresh on one host and expired on another. PHP's ini settings
     * must never be an authorization input.
     */
    $payload = evidenceFor([evidenceFactor()])->toArray();
    $payload['factors'][0]['satisfied_at'] = '2026-08-29 10:00:00';

    expect(fn () => AssuranceEvidence::fromArray($payload))->toThrow(MalformedEvidence::class);
});

it('persists an unambiguous instant, whatever the process timezone is', function (): void {
    /*
     * Asserting that two offsets parse to the same instant only proves PHP can
     * parse offsets. The real risk is that toArray() renders without one and
     * fromArray() then resolves it locally. So: serialize under one default
     * timezone, decode under another, and require the same instant back.
     */
    $original = date_default_timezone_get();

    try {
        date_default_timezone_set('America/Los_Angeles');
        $payload = evidenceFor([evidenceFactor('password', '2026-08-29T10:00:00+00:00')])->toArray();

        date_default_timezone_set('Asia/Tokyo');
        $restored = AssuranceEvidence::fromArray($payload);

        expect($restored->weakestSatisfiedAt()->getTimestamp())
            ->toBe((new DateTimeImmutable('2026-08-29T10:00:00+00:00'))->getTimestamp());
    } finally {
        date_default_timezone_set($original);
    }
});
