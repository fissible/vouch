<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionEvidence;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Illuminate\Foundation\Testing\RefreshDatabase;
use OTPHP\TOTP;

uses(RefreshDatabase::class);

/*
 * 2.4 Task 2a — the proof that gets persisted is the proof that was presented.
 *
 * Every other test in this task hands SessionLifecycle an AuthSuccess built by
 * the test itself, which proves only that whatever a caller supplies is stored.
 * These drive the real AuthFlow: a real policy, real credentials, real
 * verification, real satisfaction timestamps -- and then assert what landed in
 * the row.
 *
 * A CORRECTED DECISION. An earlier draft of this contract persisted
 * AuthSuccess::$factors -- every factor satisfied during the attempt -- and
 * argued that it coincided with the policy's selected set because the flow
 * terminates on satisfaction. That argument is false, and the counterexample is
 * concrete:
 *
 *     any_of: [ all_of: [password, totp], all_of: [passkey, sms] ]
 *
 * Satisfy password, then passkey, then sms. The flow terminates on the third
 * factor, but SatisfiabilityEvaluator returns the winning branch only, so
 * usedFactors is [passkey, sms] while the attempt's satisfied set holds all
 * three. An all_of policy can never show the divergence, which is why the first
 * draft's tests could not catch it.
 *
 * So Task 2a persists the VERDICT's set, per addendum section 3, and derives
 * `acr` from that same set. One set, two views. Persisting the broader set
 * while deriving the level from it would let a factor the policy never selected
 * raise the recorded assurance; deriving from one and persisting the other
 * would reintroduce the acr/proof disagreement this task exists to remove.
 *
 * That requires the verdict to survive AuthFlow::targetState(), which today
 * computes it, reads ->satisfied, and discards ->usedFactors.
 */

const PROOF_BINDING_SOURCE = 'selected-proof-session';

function proofBinding(): string
{
    return SessionBinding::for(PROOF_BINDING_SOURCE, BindingDomain::Attempt);
}

/** @param array<string, mixed> $document */
function proofPolicy(array $document): void
{
    AuthPolicy::create(['tenant_id' => null, 'scope' => 'login', 'document' => $document, 'posture' => 'friendly']);
}

function proofIdentified(int $userId = 7): string
{
    AuthIdentifier::create([
        'user_id' => $userId, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);

    $begun = app(AuthFlow::class)->advance(new FlowRequest(null, 'begin', [], proofBinding()));
    assert($begun instanceof Continuing);
    $handle = $begun->handle;
    assert(is_string($handle));

    app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', ['identifier' => 'ada@acme.example'], proofBinding()));

    return $handle;
}

/** @param array<string, mixed> $input */
function proofSubmit(string $handle, array $input): mixed
{
    return app(AuthFlow::class)->advance(new FlowRequest($handle, 'submit', $input, proofBinding()));
}

function proofTotpCode(int $userId = 7): string
{
    $secret = (string) AuthCredential::query()
        ->where('user_id', $userId)->where('type', 'totp')->firstOrFail()->secret;

    return TOTP::createFromSecret($secret)->now();
}

it('persists exactly the factors a single-factor policy required', function (): void {
    proofPolicy(['all_of' => ['password']]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);

    $handle = proofIdentified();
    $result = proofSubmit($handle, ['password' => 'correct horse battery staple']);

    assert($result instanceof Authenticated);

    session()->start();
    app(SessionLifecycle::class)->establish($result->success);

    $evidence = SessionEvidence::for(\Fissible\Vouch\Models\AuthSession::query()->firstOrFail());

    expect($evidence)->not->toBeNull()
        ->and(array_map(static fn ($f): string => $f->factorId, $evidence->factors))->toBe(['password'])
        ->and($evidence->derivedAcr())->toBe('aal1');
});

it('persists both factors of an all_of policy, and no others', function (): void {
    proofPolicy(['all_of' => ['password', 'totp']]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $handle = proofIdentified();

    $continuing = proofSubmit($handle, ['password' => 'correct horse battery staple']);
    expect($continuing)->toBeInstanceOf(Continuing::class);

    $result = proofSubmit($handle, ['code' => proofTotpCode()]);
    assert($result instanceof Authenticated);

    session()->start();
    app(SessionLifecycle::class)->establish($result->success);

    $evidence = SessionEvidence::for(\Fissible\Vouch\Models\AuthSession::query()->firstOrFail());

    expect(array_map(static fn ($f): string => $f->factorId, $evidence->factors))
        ->toEqualCanonicalizing(['password', 'totp'])
        ->and($evidence->derivedAcr())->toBe('aal2');
});

it('anchors recency to the first factor of a multi-step login', function (): void {
    /*
     * The two factors are satisfied twelve minutes apart in real flow time.
     * The persisted anchor must be the PASSWORD's timestamp -- the older one --
     * because a session is only as fresh as its stalest evidence. An
     * implementation writing the newest passes every other test in this file.
     */
    proofPolicy(['all_of' => ['password', 'totp']]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $this->travelTo(new DateTimeImmutable('2026-08-13T10:00:00+00:00'));
    $handle = proofIdentified();
    proofSubmit($handle, ['password' => 'correct horse battery staple']);

    $this->travelTo(new DateTimeImmutable('2026-08-13T10:12:00+00:00'));
    $result = proofSubmit($handle, ['code' => proofTotpCode()]);
    assert($result instanceof Authenticated);

    session()->start();
    app(SessionLifecycle::class)->establish($result->success);

    $session = \Fissible\Vouch\Models\AuthSession::query()->firstOrFail();

    expect($session->weakest_satisfied_at->getTimestamp())
        ->toBe((new DateTimeImmutable('2026-08-13T10:00:00+00:00'))->getTimestamp())
        ->and(SessionEvidence::for($session)->weakestSatisfiedAt()->getTimestamp())
        ->toBe((new DateTimeImmutable('2026-08-13T10:00:00+00:00'))->getTimestamp());
});

it('persists the same set the flow derived its acr from', function (): void {
    /*
     * The invariant behind the recorded decision above: whatever set is chosen,
     * the stored acr and the proof must be two views of ONE set. This compares
     * the level the flow published against the level re-derived from the row,
     * which is the only thing that can catch the two drifting apart.
     */
    proofPolicy(['all_of' => ['password', 'totp']]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $handle = proofIdentified();
    proofSubmit($handle, ['password' => 'correct horse battery staple']);
    $result = proofSubmit($handle, ['code' => proofTotpCode()]);
    assert($result instanceof Authenticated);

    session()->start();
    app(SessionLifecycle::class)->establish($result->success);

    $session = \Fissible\Vouch\Models\AuthSession::query()->firstOrFail();

    expect(SessionEvidence::for($session)->derivedAcr())->toBe($result->success->acr)
        ->and($session->acr)->toBe($result->success->acr)
        ->and(SessionEvidence::for($session)->factors)->toEqual($result->success->factors);
});

it('carries the policy-selected factors, not everything satisfied', function (): void {
    /*
     * The invariant that the corrected decision rests on. AuthSuccess must
     * expose the verdict's selected set; without it SessionLifecycle has no way
     * to persist anything but the broader one.
     */
    proofPolicy(['all_of' => ['password', 'totp']]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $handle = proofIdentified();
    proofSubmit($handle, ['password' => 'correct horse battery staple']);
    $result = proofSubmit($handle, ['code' => proofTotpCode()]);
    assert($result instanceof Authenticated);

    expect($result->success->selectedFactors)->toBeArray()
        ->and(array_map(static fn ($f): string => $f->factorId, $result->success->selectedFactors))
        ->toEqualCanonicalizing(['password', 'totp']);
});
