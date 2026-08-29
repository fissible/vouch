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
 * A RECORDED DECISION, because the addendum is ambiguous here. Section 3 calls
 * the selected proof "the exact SatisfiedFactor set the policy evaluation used
 * to reach the required level". AuthFlow computes exactly that -- the Verdict's
 * usedFactors, at AuthFlow.php:607 -- and discards it, passing the attempt's
 * full satisfied set to AuthSuccess instead. Task 2a persists AuthSuccess's
 * set, deliberately, for two reasons:
 *
 *   1. `acr` is already derived from that same set. Persisting a different set
 *      beside it would manufacture a fresh disagreement between the stored
 *      level and the stored proof -- the precise defect this task exists to
 *      remove.
 *   2. The flow terminates the moment the policy is satisfied, so the attempt
 *      cannot accumulate factors beyond the ones that reached the level. The
 *      two sets coincide in the flow as written; the tests below hold that
 *      claim to the real implementation rather than to this comment.
 *
 * If they ever diverge, these fail, and the addendum's wording -- not the
 * implementation -- is what needs revisiting.
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
