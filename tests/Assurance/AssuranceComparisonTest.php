<?php

declare(strict_types=1);

use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\AssuranceComparison;
use Fissible\Vouch\Assurance\AssuranceOutcome;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Psr\Clock\ClockInterface;

/*
 * 2.4 Task 2a — one comparator, a typed verdict.
 *
 * The comparator is where "one policy, two renderings" is either true or a
 * slogan: session and token evidence are judged by the same code against the
 * same requirement, so a requirement cannot come to mean different things
 * depending on which surface presented the credential.
 *
 * It returns an outcome rather than a boolean because Task 4 must tell a client
 * WHY it was refused. RFC 9470 distinguishes "authenticate more strongly" from
 * "authenticate more recently", and a boolean forces the response layer to
 * re-derive that distinction -- which means re-implementing the policy, which
 * is the drift this class exists to prevent.
 */

function comparisonClock(string $now): ClockInterface
{
    return new class($now) implements ClockInterface {
        public function __construct(private string $now) {}

        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable($this->now);
        }
    };
}

function compareFully(
    ?AssuranceEvidence $evidence,
    string|array $requirement,
    string $now = '2026-08-29T10:01:00+00:00',
    ?string $tenantId = null,
): AssuranceComparison {
    return app(EvidenceComparator::class)->compare(
        $evidence,
        AssuranceRequirement::from($requirement),
        comparisonClock($now),
        $tenantId,
    );
}

function compareEvidence(
    ?AssuranceEvidence $evidence,
    string|array $requirement,
    string $now = '2026-08-29T10:01:00+00:00',
    ?string $tenantId = null,
): AssuranceOutcome {
    return compareFully($evidence, $requirement, $now, $tenantId)->outcome;
}


/*
 * Requirement parsing. The published bare-string form must keep working, and
 * the expanded form must be strict: a requirement that silently parsed to
 * level-only would stop enforcing recency while still looking configured.
 */

it('still accepts the bare level string published in 0.1.1', function (): void {
    $requirement = AssuranceRequirement::from('aal2');

    expect($requirement->level)->toBe('aal2')
        ->and($requirement->maxAgeSeconds())->toBeNull();
});

it('accepts the expanded form with an ISO-8601 max age', function (): void {
    $requirement = AssuranceRequirement::from(['level' => 'aal2', 'max_age' => 'PT15M']);

    expect($requirement->level)->toBe('aal2')
        ->and($requirement->maxAgeSeconds())->toBe(900);
});

it('renders max age to the integer seconds RFC 9470 puts on the wire', function (string $iso, int $seconds): void {
    // Config takes ISO-8601 because it maps onto DateInterval. The wire takes
    // seconds because RFC 9470 section 3 says so. Convert once, here.
    expect(AssuranceRequirement::from(['level' => 'aal2', 'max_age' => $iso])->maxAgeSeconds())->toBe($seconds);
})->with([
    ['PT15M', 900],
    ['PT1H', 3600],
    ['P1D', 86400],
    ['PT0S', 0],
]);

it('refuses a malformed requirement rather than dropping the recency half', function (mixed $bad): void {
    expect(fn () => AssuranceRequirement::from($bad))->toThrow(InvalidArgumentException::class);
})->with([
    'unknown level' => ['aal9'],
    'bad iso' => [['level' => 'aal2', 'max_age' => '15 minutes']],
    'seconds instead of iso' => [['level' => 'aal2', 'max_age' => 900]],
    'missing level' => [['max_age' => 'PT15M']],
    'unknown key' => [['level' => 'aal2', 'maxage' => 'PT15M']],
    'negative interval' => [['level' => 'aal2', 'max_age' => 'PT-15M']],
]);

/*
 * The four outcomes. Each must be reachable and distinguishable, because Task 4
 * renders a different response for each.
 */

it('reports sufficient when the proof meets the level', function (): void {
    expect(compareEvidence(evidenceFor([evidenceFactor()]), 'aal1'))
        ->toBe(AssuranceOutcome::Sufficient);
});

it('reports insufficient level when the requirement outranks the proof', function (): void {
    // Ordered comparison, as on the session path: a knowledge factor alone does
    // not reach aal2.
    expect(compareEvidence(evidenceFor([evidenceFactor()]), 'aal2'))
        ->toBe(AssuranceOutcome::InsufficientLevel);
});

it('reports insufficient recency when the level holds but the proof is stale', function (): void {
    expect(compareEvidence(
        evidenceFor([evidenceFactor('password', '2026-08-29T10:00:00+00:00')]),
        ['level' => 'aal1', 'max_age' => 'PT15M'],
        now: '2026-08-29T10:15:01+00:00',
    ))->toBe(AssuranceOutcome::InsufficientRecency);
});

it('reports insufficient level, not recency, when BOTH fail', function (): void {
    /*
     * Precedence is a policy decision, not an implementation detail. A client
     * told only "authenticate more recently" would re-present the same weak
     * factor, satisfy the recency half, and be refused again on the level --
     * a loop that looks to the user like a broken login. Report the stronger
     * demand, which subsumes the other: a fresh step-up satisfies both.
     */
    expect(compareEvidence(
        evidenceFor([evidenceFactor('password', '2026-07-01T10:00:00+00:00')]),
        ['level' => 'aal2', 'max_age' => 'PT15M'],
        now: '2026-08-29T10:00:00+00:00',
    ))->toBe(AssuranceOutcome::InsufficientLevel);
});

it('reports invalid evidence when there is none at all', function (): void {
    // Distinct from InsufficientLevel: an unauthenticated request is not a
    // step-up candidate, and Task 4 must not answer it with a challenge that
    // implies re-authenticating would help.
    expect(compareEvidence(null, 'aal1'))->toBe(AssuranceOutcome::InvalidEvidence);
});

it('never reports sufficient for any outcome but Sufficient', function (): void {
    // isSufficient() is the call-site convenience. If it ever answers true for
    // a refusal case, every middleware built on it fails open at once.
    foreach (AssuranceOutcome::cases() as $case) {
        expect($case->isSufficient())->toBe($case === AssuranceOutcome::Sufficient);
    }
});

/*
 * Recency.
 */

it('accepts a proof still inside the recency window', function (): void {
    expect(compareEvidence(
        evidenceFor([evidenceFactor('password', '2026-08-29T10:00:00+00:00')]),
        ['level' => 'aal1', 'max_age' => 'PT15M'],
        now: '2026-08-29T10:14:59+00:00',
    ))->toBe(AssuranceOutcome::Sufficient);
});

it('accepts a proof exactly at the recency boundary', function (): void {
    /*
     * The boundary is the whole reason this uses a fixed clock. An off-by-one
     * either expires a valid credential a second early or honours a stale one a
     * second late, and neither shows up in a test that tries only "recent" and
     * "ancient".
     */
    expect(compareEvidence(
        evidenceFor([evidenceFactor('password', '2026-08-29T10:00:00+00:00')]),
        ['level' => 'aal1', 'max_age' => 'PT15M'],
        now: '2026-08-29T10:15:00+00:00',
    ))->toBe(AssuranceOutcome::Sufficient);
});

it('measures recency from the OLDEST factor in the proof', function (): void {
    /*
     * A fresh second factor must not launder a stale first one. Both factors
     * here are individually enough for aal1; only the pair's oldest member is
     * outside the window, so a comparator reading the newest passes this.
     */
    expect(compareEvidence(
        evidenceFor([
            evidenceFactor('password', '2026-07-01T10:00:00+00:00'),
            evidenceFactor('totp', '2026-08-29T10:00:00+00:00', FactorStrength::Possession, 'cred-2'),
        ]),
        ['level' => 'aal1', 'max_age' => 'PT1H'],
        now: '2026-08-29T10:30:00+00:00',
    ))->toBe(AssuranceOutcome::InsufficientRecency);
});

it('applies no recency limit when the requirement sets none', function (): void {
    // A level-only requirement must not acquire a default max age, or every
    // requirement published in 0.1.1 quietly starts expiring.
    expect(compareEvidence(
        evidenceFor([evidenceFactor('password', '2020-01-01T10:00:00+00:00')]),
        'aal1',
    ))->toBe(AssuranceOutcome::Sufficient);
});

/*
 * Tenancy. Evidence minted under one tenant's policy must never authorize under
 * another's, and global is not a wildcard in either direction.
 */

it('refuses evidence minted under a different tenant', function (string|null $evidenceTenant, string|null $required, AssuranceOutcome $expected): void {
    expect(compareEvidence(
        evidenceFor([evidenceFactor()], $evidenceTenant),
        'aal1',
        tenantId: $required,
    ))->toBe($expected);
// Lazy dataset: the cases name an enum that does not exist until this task is
// implemented, and an eagerly-evaluated dataset aborts collection for the whole
// file rather than failing this one test.
})->with(static fn (): array => [
    'matching tenant' => ['acme', 'acme', AssuranceOutcome::Sufficient],
    'different tenant' => ['acme', 'other', AssuranceOutcome::InvalidEvidence],
    'global evidence, tenant route' => [null, 'acme', AssuranceOutcome::InvalidEvidence],
    'tenant evidence, global route' => ['acme', null, AssuranceOutcome::InvalidEvidence],
    'both global' => [null, null, AssuranceOutcome::Sufficient],
]);

it('classes a tenant mismatch as invalid evidence, not as a weak level', function (): void {
    /*
     * Deliberate mapping, recorded so it cannot be re-decided by accident. A
     * cross-tenant credential is not weak -- it may be aal3. It is simply not
     * evidence here, so Task 4 must refuse it outright rather than answer with
     * a step-up challenge inviting the holder to strengthen a credential that
     * will never apply.
     */
    $strong = evidenceFor([
        evidenceFactor('password', '2026-08-29T10:00:00+00:00'),
        evidenceFactor('totp', '2026-08-29T10:00:00+00:00', FactorStrength::Possession, 'cred-2'),
    ], 'acme');

    expect($strong->derivedAcr())->toBe('aal2')
        ->and(compareEvidence($strong, 'aal1', tenantId: 'other'))->toBe(AssuranceOutcome::InvalidEvidence);
});

/*
 * The internal cause.
 *
 * The four outcomes are what a CLIENT is told, and deliberately coarse: several
 * distinct server-side conditions must all render as "this evidence does not
 * apply", because telling a caller which one would describe the tenant layout
 * to someone holding a credential from another tenant.
 *
 * Operators need the opposite. A support engineer looking at a spike of
 * refusals has to be able to separate a tenant misconfiguration from corrupted
 * rows from an installed base that has not re-authenticated since the upgrade,
 * and an enum with one InvalidEvidence case cannot express that. The reason
 * rides alongside the outcome and is never rendered.
 */

it('carries an internal reason distinct from the rendered outcome', function (): void {
    $comparison = compareFully(evidenceFor([evidenceFactor()], 'acme'), 'aal1', tenantId: 'other');

    expect($comparison->outcome)->toBe(AssuranceOutcome::InvalidEvidence)
        ->and($comparison->reason)->toBe(AssuranceReason::TenantMismatch);
});

it('separates the causes that all render as invalid evidence', function (): void {
    // Every one of these is InvalidEvidence to a client. If any two shared a
    // reason, the operational signal they exist to provide would be lost.
    $absent = compareFully(null, 'aal1');
    $mismatched = compareFully(evidenceFor([evidenceFactor()], 'acme'), 'aal1', tenantId: 'other');

    expect($absent->outcome)->toBe($mismatched->outcome)
        ->and($absent->reason)->toBe(AssuranceReason::NoEvidence)
        ->and($absent->reason)->not->toBe($mismatched->reason);
});

it('reports a reason for the sufficient case too', function (): void {
    // A nullable reason would make "no reason recorded" ambiguous between
    // success and an unhandled branch.
    $comparison = compareFully(evidenceFor([evidenceFactor()]), 'aal1');

    expect($comparison->outcome)->toBe(AssuranceOutcome::Sufficient)
        ->and($comparison->reason)->toBe(AssuranceReason::Sufficient);
});

it('gives each refusal outcome its own reason', function (): void {
    $weak = compareFully(evidenceFor([evidenceFactor()]), 'aal2');
    $stale = compareFully(
        evidenceFor([evidenceFactor('password', '2026-08-29T10:00:00+00:00')]),
        ['level' => 'aal1', 'max_age' => 'PT15M'],
        now: '2026-08-29T10:15:01+00:00',
    );

    expect($weak->reason)->toBe(AssuranceReason::LevelTooWeak)
        ->and($stale->reason)->toBe(AssuranceReason::ProofTooOld);
});

it('never contradicts itself between outcome and reason', function (): void {
    // The pair is redundant by construction, and redundancy that can disagree
    // is worse than either half alone: an audit log and a response could
    // describe different refusals for the same request.
    foreach (AssuranceReason::cases() as $reason) {
        expect($reason->outcome()->isSufficient())->toBe($reason === AssuranceReason::Sufficient);
    }
});

/*
 * The assurance lattice.
 *
 * These arrived from tests/Http/OpenRedirectTest.php, where they had been
 * testing AssuranceComparator::isSufficient(). That method is removed by this
 * task; the properties it protected are not, so they are re-expressed against
 * the evidence comparator rather than deleted with their subject.
 */

it('orders every derivable level against every requirement', function (): void {
    /*
     * The ORDER constant IS the lattice. Removing a rung does not error --
     * strength() simply refuses everything involving that level while every
     * other comparison keeps working -- so a missing rung is invisible except to
     * a test that names them all. Sufficiency must hold downwards and fail
     * upwards at every step.
     *
     * Only aal1 and aal2 are derivable: NistAssuranceVocabulary caps at aal2 by
     * design, and aal0 requires zero eligible credentials, which the evidence
     * value refuses to exist with. An aal3 requirement is therefore always
     * unsatisfiable here, which is the honest answer rather than an omission.
     */
    $derivable = [
        'aal1' => [evidenceFactor()],
        'aal2' => [evidenceFactor(), evidenceFactor('totp', '2026-08-29T10:00:00+00:00', FactorStrength::Possession, 'cred-2')],
    ];
    $order = ['aal0' => 0, 'aal1' => 1, 'aal2' => 2, 'aal3' => 3];

    foreach ($derivable as $held => $factors) {
        $evidence = evidenceFor($factors);
        expect($evidence->derivedAcr())->toBe($held);

        foreach ($order as $want => $wantIndex) {
            expect(compareEvidence($evidence, $want)->isSufficient())
                ->toBe($order[$held] >= $wantIndex, "held {$held} vs required {$want}");
        }
    }
});

it('cannot hold an unrecognised level, by construction', function (): void {
    /*
     * The old comparator had to guard both positions, because a stored acr of
     * 'aal9' compared numerically coerces to 0 and SATISFIES a requirement of
     * aal0. Evidence carries no stored level at all -- it is derived from the
     * factors by the vocabulary -- so the unknown-held case is not guarded
     * against, it is unrepresentable. Only the requirement side can still be
     * unknown, and that is refused at parse time.
     */
    expect(fn () => AssuranceRequirement::from('aal9'))->toThrow(InvalidArgumentException::class)
        ->and(evidenceFor([evidenceFactor()])->derivedAcr())->toBeIn(['aal0', 'aal1', 'aal2', 'aal3']);
});

it('refuses a proof made only of recovery factors', function (): void {
    /*
     * Recovery grants a restricted grace session and never contributes to a
     * policy, so a recovery-only proof derives zero eligible credentials -- and
     * the vocabulary names that aal0, which would then SATISFY an aal0
     * requirement. Refusing the value outright closes that path at the type
     * level rather than relying on every requirement being aal1 or stronger.
     */
    expect(fn () => evidenceFor([evidenceFactor('recovery_code', '2026-08-29T10:00:00+00:00', FactorStrength::Recovery, 'cred-r')]))
        ->toThrow(Fissible\Vouch\Assurance\MalformedEvidence::class);
});
