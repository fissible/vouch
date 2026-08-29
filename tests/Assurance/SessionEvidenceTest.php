<?php

declare(strict_types=1);

use Fissible\Vouch\Assurance\AssuranceOutcome;
use Fissible\Vouch\Assurance\AssuranceReason;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\RevokedReason;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Fissible\Vouch\Sessions\SessionRotationFailed;
use Fissible\Vouch\Tokens\SubjectKey;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/*
 * 2.4 Task 2a — the session write path, end to end.
 *
 * This is the file that makes the addendum's central claim true rather than
 * aspirational. Before it, SessionLifecycle wrote amr and acr and nothing else,
 * and session authorization compared the cached acr string. Every test here
 * exercises the real production writer: a real AuthSuccess, a real
 * establish(), a real row, read back through the adapter and judged by the
 * same comparator the token path uses.
 *
 * Tests that hand-build a row prove only that the reader can read what the test
 * wrote. Where a hand-built row is unavoidable -- legacy and corruption cases,
 * which the writer by definition cannot produce -- it is called out.
 */

function proofFactor(
    string $id = 'password',
    string $at = '2026-08-13T10:00:00+00:00',
    FactorStrength $strength = FactorStrength::Knowledge,
    string $credentialId = 'cred-1',
): SatisfiedFactor {
    return new SatisfiedFactor(
        factorId: $id,
        credentialId: $credentialId,
        kind: FactorKind::Knowledge,
        strength: $strength,
        isMultiFactor: false,
        userVerified: false,
        phishingResistant: false,
        authenticatorId: null,
        satisfiedAt: new DateTimeImmutable($at),
    );
}

/** @param list<SatisfiedFactor> $factors */
function proofSuccess(array $factors = [], int $userId = 7, ?string $acr = null): AuthSuccess
{
    $factors = $factors === [] ? [proofFactor()] : $factors;
    $facts = AssuranceFacts::fromFactors($factors);

    return new AuthSuccess($userId, $factors, $facts, $acr ?? 'aal1', 'ignored');
}

function establishSession(AuthSuccess $success): AuthSession
{
    session()->start();
    app(SessionLifecycle::class)->establish($success);

    return AuthSession::query()->firstOrFail();
}

/*
 * The writer.
 */

it('persists the proof at the login-success boundary', function (): void {
    $session = establishSession(proofSuccess());

    // The column, not the model accessor: an accessor that helpfully derives a
    // proof from amr would satisfy an assertion made through the model while
    // the database still held nothing.
    $stored = DB::table('auth_sessions')->where('id', $session->id)->value('assurance_proof');

    expect($stored)->not->toBeNull()
        ->and(json_decode(stringValue($stored), true))->toBeArray();
});

it('reconstructs the exact factors the flow presented', function (): void {
    $factors = [
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ];

    $evidence = SessionEvidence::for(establishSession(proofSuccess($factors)));

    expect($evidence)->not->toBeNull()
        ->and($evidence->factors)->toEqual($factors);
});

it('stores the subject key the token path would render for the same user', function (): void {
    /*
     * The two surfaces must agree on identity or "one policy" is false at the
     * subject level: the same person would be a different principal depending on
     * how they authenticated, and the subject-mismatch refusals below would
     * reject every legitimate cross-surface case rather than an attack.
     *
     * Asserted against getMorphClass(), which is what the Sanctum issuer already
     * uses (SanctumTokenIssuer:91). An earlier draft compared against
     * config('auth.providers.users.model') directly; those two agree only while
     * no morph map is registered, so it would have passed here while producing
     * session evidence that can never bind to a real token.
     */
    $model = stringValue(config('auth.providers.users.model'));
    $principal = new $model;

    $evidence = SessionEvidence::for(establishSession(proofSuccess(userId: 7)));

    expect($evidence->subject->render())
        ->toBe(SubjectKey::of($principal->getMorphClass(), 7)->render());
});

it('canonicalizes the subject through the morph map, as the token path does', function (): void {
    /*
     * THE discriminating case. With a morph map registered, getMorphClass()
     * returns the ALIAS while the configured model class stays fully qualified,
     * and Sanctum writes that same alias into tokenable_type. A session writer
     * that resolved the class name instead would mint evidence whose provider
     * half can never match a token's, so no session and token for one user would
     * ever agree on whom they belong to. The test above passes under either
     * implementation; this one does not.
     */
    $model = stringValue(config('auth.providers.users.model'));

    // morphMap(), not enforceMorphMap(): the latter also sets Laravel's global
    // requireMorphMap flag, which resetting the map alone does NOT clear, so
    // every model in every later suite throws ClassMorphViolationException.
    // Registering the alias is all this needs.
    Relation::morphMap(['vouch_user' => $model], false);

    try {
        $session = establishSession(proofSuccess(userId: 7));
        $read = SessionEvidence::read(AuthSession::query()->findOrFail($session->id));

        // The writer stores the alias...
        expect($read->evidence)->not->toBeNull()
            ->and($read->evidence->subject->provider)->toBe('vouch_user')
            ->and($read->evidence->subject->render())->toBe('vouch_user:7')
            // ...and the reader ACCEPTS it. Storing the right thing while the
            // reader rejected it would lock every mapped host out completely,
            // and the write assertion alone cannot tell the difference.
            ->and($read->reason)->toBe(AssuranceReason::Sufficient);

        /*
         * And the raw class name is FOREIGN while the map is active. Under a
         * morph map the alias IS the canonical provider, so a proof carrying
         * the FQCN was minted under a different identity scheme -- by an older
         * version, or by a host that registered the map after the fact. Binding
         * it anyway would silently accept evidence from before the boundary
         * moved.
         */
        DB::table('auth_sessions')->where('id', $session->id)->update([
            'assurance_proof' => json_encode(
                (new \Fissible\Vouch\Assurance\AssuranceEvidence(
                    \Fissible\Vouch\Tokens\SubjectKey::of($model, 7),
                    null,
                    [proofFactor('password', '2026-08-13T10:00:00+00:00')],
                ))->toArray(),
                JSON_THROW_ON_ERROR,
            ),
        ]);

        expect(SessionEvidence::read(AuthSession::query()->findOrFail($session->id))->reason)
            ->toBe(AssuranceReason::SubjectMismatch);
    } finally {
        Relation::morphMap([], false);
    }
});

it('anchors the persisted recency column to the oldest factor', function (): void {
    /*
     * The column that carries this was named last_factor_at, while its own
     * migration comment said "oldest satisfied factor". 2a renames it to
     * weakest_satisfied_at so the name and the semantics cannot disagree --
     * and this asserts the value, because the rename alone changes nothing.
     */
    $session = establishSession(proofSuccess([
        proofFactor('password', '2026-07-01T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:00:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    expect($session->weakest_satisfied_at)->not->toBeNull()
        ->and($session->weakest_satisfied_at->toIso8601String())
        ->toBe('2026-07-01T10:00:00+00:00');
});

it('still writes acr, and still does not authorize from it', function (): void {
    /*
     * acr remains persisted: hosts index and display it, and the addendum keeps
     * it as a projection. The point is that it is now derivable from the row
     * beside it rather than being the only record of what happened.
     */
    $session = establishSession(proofSuccess());

    expect($session->acr)->toBe('aal1')
        ->and(SessionEvidence::for($session)->derivedAcr())->toBe('aal1');
});

it('replaces the proof on rotation rather than accumulating rows', function (): void {
    session()->start();
    $lifecycle = app(SessionLifecycle::class);

    $lifecycle->establish(proofSuccess([proofFactor('password', '2026-08-13T10:00:00+00:00')]));
    $lifecycle->establish(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T11:00:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    $session = AuthSession::query()->firstOrFail();

    expect(AuthSession::query()->count())->toBe(1)
        ->and(SessionEvidence::for($session)->factors)->toHaveCount(2)
        ->and(SessionEvidence::for($session)->derivedAcr())->toBe('aal2');
});

it('fails the login closed when the proof cannot be serialized', function (): void {
    /*
     * The ordering contract in SessionLifecycle's docblock is what makes every
     * failure land on an unauthenticated session. Adding a second thing to write
     * is exactly the change that breaks it, so it is re-asserted against the new
     * failure source rather than assumed to still hold.
     *
     * The injection is an AuthSuccess carrying no factors -- a shape this
     * codebase already constructs (tests/Http/PayloadContractTest.php:91) and
     * one an empty proof cannot be built from. Chosen over dropping the column
     * at runtime, which is DDL: MySQL commits it implicitly and would tear down
     * the surrounding test transaction instead of exercising the failure.
     */
    session()->start();
    $before = session()->getId();

    $empty = new AuthSuccess(7, [], AssuranceFacts::fromFactors([]), 'aal1', 'ignored');

    expect(fn () => app(SessionLifecycle::class)->establish($empty))
        ->toThrow(SessionRotationFailed::class)
        ->and(session()->getId())->not->toBe($before)
        ->and(AuthSession::query()->count())->toBe(0);
});

it('leaves the prior session untouched when a rotation fails', function (): void {
    /*
     * Atomicity, from the direction that actually costs someone something. A
     * failed re-establish must not half-write: a row left carrying the new
     * binding with the old proof, or the new proof with the old binding, is a
     * session whose evidence describes a different login than its identity.
     */
    session()->start();
    $lifecycle = app(SessionLifecycle::class);
    $lifecycle->establish(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    $before = AuthSession::query()->firstOrFail()->only([
        'session_binding', 'amr', 'acr', 'assurance_proof', 'weakest_satisfied_at',
    ]);

    try {
        $lifecycle->establish(new AuthSuccess(7, [], AssuranceFacts::fromFactors([]), 'aal1', 'ignored'));
    } catch (SessionRotationFailed) {
        // Expected; the assertion is about what the row looks like afterwards.
    }

    expect(AuthSession::query()->count())->toBe(1)
        ->and(AuthSession::query()->firstOrFail()->only([
            'session_binding', 'amr', 'acr', 'assurance_proof', 'weakest_satisfied_at',
        ]))->toEqual($before);
});

it('does not leave valid proof on a session revoked alongside it', function (): void {
    /*
     * revokeSiblings() marks rows revoked without touching their proof, which is
     * correct -- the proof is a record of what happened and revocation is not a
     * claim that it did not. What must never happen is the reverse: a revoked
     * row whose proof still authorizes. The revocation check has to come before
     * the evidence is even read.
     */
    session()->start();
    $lifecycle = app(SessionLifecycle::class);
    $lifecycle->establish(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    $session = AuthSession::query()->firstOrFail();
    $lifecycle->revokeSiblings(7, 'a-different-binding', RevokedReason::CredentialChanged);
    $session->refresh();

    expect($session->revoked_at)->not->toBeNull()
        // The evidence survives as a record...
        ->and($session->assurance_proof)->not->toBeNull()
        // ...and grants nothing.
        ->and(SessionEvidence::for($session))->toBeNull();
});

/*
 * The read path.
 */

it('judges a live session through the shared comparator', function (): void {
    // Named for what it is. Task 2 adds the token adapter and the claim that
    // both surfaces share this comparator becomes testable then; asserting it
    // here, with only one adapter in existence, would be asserting nothing.
    $session = establishSession(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));

    $comparator = app(EvidenceComparator::class);
    $clock = new class implements \Psr\Clock\ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
        }
    };

    expect($comparator->compare(SessionEvidence::for($session), AssuranceRequirement::from('aal2'), $clock, null)->outcome)
        ->toBe(AssuranceOutcome::Sufficient)
        ->and($comparator->compare(SessionEvidence::for($session), AssuranceRequirement::from('aal3'), $clock, null)->outcome)
        ->toBe(AssuranceOutcome::InsufficientLevel)
        ->and($comparator->compare(
            SessionEvidence::for($session),
            AssuranceRequirement::from(['level' => 'aal2', 'max_age' => 'PT1M']),
            $clock,
            null,
        )->outcome)->toBe(AssuranceOutcome::InsufficientRecency);
});

it('refuses a session whose persisted acr disagrees with its factors', function (): void {
    /*
     * THE test for the addendum's claim. A row is tampered so acr says aal3
     * while the proof holds a single knowledge factor. Authorization that reads
     * the cached level passes; authorization that re-derives from the proof
     * refuses. Nothing else in this suite distinguishes those two
     * implementations.
     */
    $session = establishSession(proofSuccess());
    DB::table('auth_sessions')->where('id', $session->id)->update(['acr' => 'aal3']);
    $session->refresh();

    expect($session->acr)->toBe('aal3')
        ->and(SessionEvidence::for($session)->derivedAcr())->toBe('aal1');
});

it('yields no evidence for a revoked session', function (): void {
    $session = establishSession(proofSuccess());
    $session->update(['revoked_at' => now()]);

    expect(SessionEvidence::for($session->fresh()))->toBeNull();
});

it('yields no evidence for a recovery-grace session', function (): void {
    // A grace session is never sufficient for anything (spec section 7.3), and
    // it must be refused before its proof is even considered.
    $session = establishSession(proofSuccess());
    $session->update(['recovery_grace_expires_at' => now()->addMinutes(10)]);

    expect(SessionEvidence::for($session->fresh()))->toBeNull();
});

it('yields no evidence for a null session', function (): void {
    expect(SessionEvidence::for(null))->toBeNull();
});

/*
 * Upgrade. A row written before 2a carries acr and amr but no proof, and no
 * writer can produce one -- so these are hand-built by necessity.
 */

it('does not adopt a legacy session that carries no proof', function (): void {
    /*
     * Re-deriving a proof from a stored acr would assert a fact nobody
     * witnessed: it would manufacture factors that were never presented, at
     * timestamps that were never recorded. The same rule the addendum already
     * applies to pre-existing tokens. The holder re-authenticates.
     */
    $legacy = AuthSession::query()->create([
        'session_binding' => str_repeat('a', 64),
        'user_id' => 7,
        'amr' => ['password', 'totp'],
        'acr' => 'aal2',
        'assurance_proof' => null,
    ]);

    expect(SessionEvidence::for($legacy))->toBeNull();
});

it('refuses a legacy session at every level, including the one it claims', function (): void {
    // A reader that fell back to acr when the proof was absent would pass an
    // aal2 requirement here, which is precisely the cached-ACR authorization
    // this task removes.
    $legacy = AuthSession::query()->create([
        'session_binding' => str_repeat('b', 64),
        'user_id' => 7,
        'amr' => ['password', 'totp'],
        'acr' => 'aal2',
        'assurance_proof' => null,
    ]);

    $clock = new class implements \Psr\Clock\ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
        }
    };

    foreach (['aal1', 'aal2', 'aal3'] as $level) {
        expect(app(EvidenceComparator::class)->compare(
            SessionEvidence::for($legacy),
            AssuranceRequirement::from($level),
            $clock,
            null,
        )->outcome)->toBe(AssuranceOutcome::InvalidEvidence);
    }
});

it('refuses a session whose stored proof is corrupt, rather than downgrading it', function (): void {
    /*
     * Distinct from the absent-proof case above: here something IS stored and
     * cannot be trusted. Returning partial evidence would silently lower the
     * level, or -- if the unreadable factor was the oldest -- silently raise
     * the recency.
     */
    $session = establishSession(proofSuccess());
    DB::table('auth_sessions')->where('id', $session->id)
        ->update(['assurance_proof' => '{"subject":"App\\\\Models\\\\User:7","tenant_id":null,"factors":[{"factor_id":"password"}]}']);

    expect(SessionEvidence::for($session->fresh()))->toBeNull();
});

it('reads the proof through the model casts the adapter relies on', function (): void {
    /*
     * The adapter reads an Eloquent model, not a query-builder row, so the
     * casts are part of the authorization path rather than convenience. An
     * uncast assurance_proof arrives as a JSON string and every structural read
     * silently sees nothing -- which fails closed, but fails closed for every
     * session at once, and looks identical to a deployment with no evidence.
     */
    $session = establishSession(proofSuccess());

    expect($session->fresh()->assurance_proof)->toBeArray()
        ->and($session->fresh()->weakest_satisfied_at)->toBeInstanceOf(Illuminate\Support\Carbon::class);
});

it('reads the recency anchor as the same instant under any process timezone', function (): void {
    /*
     * The schema test covers the stored string; this covers the value
     * authorization actually compares. A cast that resolved the column against
     * the process timezone would shift every session's recency by the host's
     * UTC offset -- expiring credentials early in one region and honouring
     * stale ones in another.
     */
    $session = establishSession(proofSuccess([proofFactor('password', '2026-08-13T10:00:00+00:00')]));
    $expected = (new DateTimeImmutable('2026-08-13T10:00:00+00:00'))->getTimestamp();

    $original = date_default_timezone_get();

    try {
        foreach (['UTC', 'America/Los_Angeles', 'Asia/Tokyo'] as $zone) {
            date_default_timezone_set($zone);

            expect(AuthSession::query()->findOrFail($session->id)->weakest_satisfied_at->getTimestamp())
                ->toBe($expected)
                ->and(SessionEvidence::for(AuthSession::query()->findOrFail($session->id))->weakestSatisfiedAt()->getTimestamp())
                ->toBe($expected);
        }
    } finally {
        date_default_timezone_set($original);
    }
});

/*
 * The adapter's read result.
 *
 * for() answers "is there usable evidence" and collapses every reason for "no"
 * into null. That is the right shape for authorization, which must treat all of
 * them identically, and the wrong shape for operators: a spike of refusals after
 * a deploy is an installed base that has not re-authenticated, whereas the same
 * spike on a stable install is corrupted rows, and the two need different
 * responses. read() carries the cause; nothing renders it to a client.
 */

it('reports why there is no usable evidence', function (AuthSession|null $session, AssuranceReason $reason): void {
    expect(SessionEvidence::read($session)->evidence)->toBeNull()
        ->and(SessionEvidence::read($session)->reason)->toBe($reason);
})->with(static fn (): array => [
    'no session at all' => [null, AssuranceReason::NoEvidence],
    'legacy row with no proof' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('m', 64), 'user_id' => 7,
            'amr' => ['password'], 'acr' => 'aal2', 'assurance_proof' => null,
        ]),
        AssuranceReason::LegacyNoProof,
    ],
    'corrupt proof' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('n', 64), 'user_id' => 7,
            'amr' => ['password'], 'acr' => 'aal2',
            'assurance_proof' => ['subject' => 'App\\Models\\User:7', 'factors' => [['factor_id' => 'password']]],
        ]),
        AssuranceReason::ProofMalformed,
    ],
    'revoked' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('o', 64), 'user_id' => 7,
            'amr' => ['password'], 'acr' => 'aal1',
            'assurance_proof' => sessionProof(7, 'aal1'), 'revoked_at' => now(),
        ]),
        AssuranceReason::SessionRevoked,
    ],
    'recovery grace' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('p', 64), 'user_id' => 7,
            'amr' => ['recovery_code'], 'acr' => null,
            'assurance_proof' => sessionProof(7, 'aal1'),
            'recovery_grace_expires_at' => now()->addMinutes(15),
        ]),
        AssuranceReason::RecoveryGrace,
    ],
]);

it('keeps for() and read() from ever disagreeing', function (): void {
    // Two entry points onto one decision. Defining for() in terms of read()
    // rather than duplicating the checks is the only way they stay aligned, and
    // this is what holds the implementation to it.
    $live = establishSession(proofSuccess());
    $legacy = AuthSession::query()->create([
        'session_binding' => str_repeat('q', 64), 'user_id' => 7,
        'amr' => ['password'], 'acr' => 'aal2', 'assurance_proof' => null,
    ]);

    foreach ([$live, $legacy, null] as $candidate) {
        expect(SessionEvidence::for($candidate))->toEqual(SessionEvidence::read($candidate)->evidence);
    }
});

it('carries the adapter cause through the comparator', function (): void {
    /*
     * Without this the reason dies at the adapter boundary: the comparator takes
     * evidence-or-null and would report NoEvidence for a corrupt row, a legacy
     * row and an unauthenticated request alike -- which is precisely the
     * flattening read() exists to undo.
     */
    $corrupt = AuthSession::query()->create([
        'session_binding' => str_repeat('r', 64), 'user_id' => 7,
        'amr' => ['password'], 'acr' => 'aal2',
        'assurance_proof' => ['subject' => 'App\\Models\\User:7', 'factors' => [['factor_id' => 'password']]],
    ]);

    $clock = new class implements \Psr\Clock\ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
        }
    };

    $comparison = app(EvidenceComparator::class)->compare(
        SessionEvidence::read($corrupt),
        AssuranceRequirement::from('aal1'),
        $clock,
        null,
    );

    expect($comparison->outcome)->toBe(AssuranceOutcome::InvalidEvidence)
        ->and($comparison->reason)->toBe(AssuranceReason::ProofMalformed);
});

it('authorizes from the proof even when the stored level is LOWER', function (): void {
    /*
     * The converse of the tampered-upward test, and the half that stops the
     * cache becoming authoritative again by the back door. An implementation
     * that required BOTH a sufficient proof AND a sufficient stored acr passes
     * every upward-tampering test while quietly making acr a ceiling.
     *
     * It also guards the amendment to addendum section 3 directly: acr is a
     * projection, so a stale one -- written by an older version, or by a host
     * that touched the column -- must not cap what the evidence proves.
     */
    $session = establishSession(proofSuccess([
        proofFactor('password', '2026-08-13T10:00:00+00:00'),
        proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ]));
    DB::table('auth_sessions')->where('id', $session->id)->update(['acr' => 'aal1']);

    $clock = new class implements \Psr\Clock\ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
        }
    };

    $fresh = AuthSession::query()->findOrFail($session->id);

    expect($fresh->acr)->toBe('aal1')
        ->and(SessionEvidence::for($fresh)->derivedAcr())->toBe('aal2')
        ->and(app(EvidenceComparator::class)->compare(
            SessionEvidence::read($fresh),
            AssuranceRequirement::from('aal2'),
            $clock,
            null,
        )->outcome)->toBe(AssuranceOutcome::Sufficient);
});

it('carries every no-evidence cause through the comparator, not just one', function (AuthSession|null $session, AssuranceReason $reason): void {
    /*
     * The forwarding test covered ProofMalformed alone, which an implementation
     * could satisfy while flattening the other four to NoEvidence -- undoing the
     * whole point of read(). Each cause is driven through compare() here.
     */
    $clock = new class implements \Psr\Clock\ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
        }
    };

    $comparison = app(EvidenceComparator::class)->compare(
        SessionEvidence::read($session),
        AssuranceRequirement::from('aal1'),
        $clock,
        null,
    );

    expect($comparison->outcome)->toBe(AssuranceOutcome::InvalidEvidence)
        ->and($comparison->reason)->toBe($reason);
})->with(static fn (): array => [
    'absent' => [null, AssuranceReason::NoEvidence],
    'legacy' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('s', 64), 'user_id' => 7,
            'amr' => ['password'], 'acr' => 'aal2', 'assurance_proof' => null,
        ]),
        AssuranceReason::LegacyNoProof,
    ],
    'corrupt' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('t', 64), 'user_id' => 7,
            'amr' => ['password'], 'acr' => 'aal2',
            'assurance_proof' => ['subject' => 'App\\Models\\User:7', 'factors' => [['factor_id' => 'password']]],
        ]),
        AssuranceReason::ProofMalformed,
    ],
    'revoked' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('u', 64), 'user_id' => 7,
            'amr' => ['password'], 'acr' => 'aal1',
            'assurance_proof' => sessionProof(7, 'aal1'), 'revoked_at' => now(),
        ]),
        AssuranceReason::SessionRevoked,
    ],
    'grace' => [
        AuthSession::query()->create([
            'session_binding' => str_repeat('v', 64), 'user_id' => 7,
            'amr' => ['recovery_code'], 'acr' => null,
            'assurance_proof' => sessionProof(7, 'aal1'),
            'recovery_grace_expires_at' => now()->addMinutes(15),
        ]),
        AssuranceReason::RecoveryGrace,
    ],
]);

it('prefers revocation over corruption when a row is both', function (): void {
    /*
     * Overlapping invalid states need a defined precedence or the reported cause
     * depends on check order, and an operator chasing a corruption spike would
     * be reading noise. Revocation is reported: it is a deliberate act with a
     * known actor and time, whereas the proof's condition is moot once the
     * session is dead.
     */
    $both = AuthSession::query()->create([
        'session_binding' => str_repeat('w', 64), 'user_id' => 7,
        'amr' => ['password'], 'acr' => 'aal2',
        'assurance_proof' => ['subject' => 'App\\Models\\User:7', 'factors' => [['factor_id' => 'password']]],
        'revoked_at' => now(),
    ]);

    expect(SessionEvidence::read($both)->reason)->toBe(AssuranceReason::SessionRevoked);
});

it('never reports a failure reason alongside usable evidence', function (): void {
    // The valid-result invariant. A read that returned both evidence and a
    // failure cause would let a caller act on either and reach opposite
    // conclusions from the same result.
    $read = SessionEvidence::read(establishSession(proofSuccess()));

    expect($read->evidence)->not->toBeNull()
        ->and($read->reason)->toBe(AssuranceReason::Sufficient);
});

it('refuses a proof that belongs to somebody else', function (): void {
    /*
     * The subject is inside the signed-off payload, and the row is found by
     * session binding — two different identities that nothing so far required to
     * agree. A syntactically perfect proof naming user 8, sitting on user 7's
     * session row, would deserialize cleanly and derive aal2. Whatever put it
     * there (a restored backup, a bad merge, a host script copying rows), the
     * adapter must refuse rather than hand user 7 an assurance level that was
     * established for someone else.
     */
    $session = establishSession(proofSuccess(userId: 7));

    $foreign = evidenceFor([
        evidenceFactor('password', '2026-08-13T10:00:00+00:00'),
        evidenceFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
    ], null, 8)->toArray();

    DB::table('auth_sessions')->where('id', $session->id)
        ->update(['assurance_proof' => json_encode($foreign, JSON_THROW_ON_ERROR)]);

    $read = SessionEvidence::read(AuthSession::query()->findOrFail($session->id));

    expect($read->evidence)->toBeNull()
        ->and($read->reason)->toBe(AssuranceReason::SubjectMismatch);
});

it('refuses a foreign proof at the authorization boundary too', function (): void {
    // The adapter refusing is only useful if the refusal reaches a decision.
    $session = establishSession(proofSuccess(userId: 7));
    DB::table('auth_sessions')->where('id', $session->id)->update([
        'assurance_proof' => json_encode(evidenceFor([
            evidenceFactor('password', '2026-08-13T10:00:00+00:00'),
            evidenceFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
        ], null, 8)->toArray(), JSON_THROW_ON_ERROR),
    ]);

    $clock = new class implements \Psr\Clock\ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
        }
    };

    $comparison = app(EvidenceComparator::class)->compare(
        SessionEvidence::read(AuthSession::query()->findOrFail($session->id)),
        AssuranceRequirement::from('aal1'),
        $clock,
        null,
    );

    expect($comparison->outcome)->toBe(AssuranceOutcome::InvalidEvidence)
        ->and($comparison->reason)->toBe(AssuranceReason::SubjectMismatch);
});

it('refuses a proof from a different user provider', function (): void {
    /*
     * SubjectKey is (provider, id), and the id half alone is not identity. Two
     * hosts, or one host mid-migration, can both have a user 7 under different
     * models; a proof minted for Other\Models\User:7 must not authorize
     * App\Models\User:7 just because the numbers match.
     *
     * Separate from the differing-id case because an implementation comparing
     * only the numeric id passes that one and fails here.
     */
    $session = establishSession(proofSuccess(userId: 7));

    $foreign = new \Fissible\Vouch\Assurance\AssuranceEvidence(
        \Fissible\Vouch\Tokens\SubjectKey::of('Other\\Models\\User', 7),
        null,
        [
            proofFactor('password', '2026-08-13T10:00:00+00:00'),
            proofFactor('totp', '2026-08-13T10:05:00+00:00', FactorStrength::Possession, 'cred-2'),
        ],
    );

    DB::table('auth_sessions')->where('id', $session->id)
        ->update(['assurance_proof' => json_encode($foreign->toArray(), JSON_THROW_ON_ERROR)]);

    $clock = new class implements \Psr\Clock\ClockInterface {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('2026-08-13T10:10:00+00:00');
        }
    };

    $fresh = AuthSession::query()->findOrFail($session->id);
    $read = SessionEvidence::read($fresh);

    expect($read->evidence)->toBeNull()
        ->and($read->reason)->toBe(AssuranceReason::SubjectMismatch)
        ->and(app(EvidenceComparator::class)->compare(
            $read,
            AssuranceRequirement::from('aal1'),
            $clock,
            null,
        )->reason)->toBe(AssuranceReason::SubjectMismatch);
});
