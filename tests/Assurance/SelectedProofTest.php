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
 * THE DECISION, settled after two reversals, so the reasoning is recorded in
 * full rather than the conclusion alone.
 *
 * The proof is EVERY factor satisfied during the attempt -- AuthSuccess::$factors
 * -- and `acr` derives from that same set. Not the policy's selected subset.
 *
 * The sets genuinely differ; that much was established against the real
 * evaluator (see tests/Kernel/SelectedFactorSubsetTest.php, and the measured
 * case below). An earlier draft argued they coincided because the flow
 * terminates on satisfaction. That argument was false and is withdrawn.
 *
 * A second draft then swung to the verdict's selected set, on a literal reading
 * of addendum section 3. Measuring it settled the question in the other
 * direction. For the policy
 *
 *     any_of: [ all_of: [totp], all_of: [password, totp] ]
 *
 * a user who presents password AND totp -- two distinct credentials, two real
 * factors -- has the password discarded, because depth-first search satisfies
 * the cheaper branch first. Their login records aal1 and they lose every aal2
 * route. That is an availability regression produced by an implementation
 * detail of the solver, and it understates what the person actually proved.
 *
 * The distinction the addendum was reaching for is real but sits elsewhere: a
 * policy must not be inflated by factors accumulated in OTHER sessions or at
 * other times. AuthSuccess::$factors is already scoped to this attempt, so that
 * concern is met without discarding evidence the user genuinely presented.
 *
 * So: the policy decides WHETHER to authenticate; the assurance level describes
 * HOW STRONGLY. Addendum section 3 is amended to match, and the tests below
 * hold the implementation to the broad set -- an implementation that narrows to
 * the verdict fails them.
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

it('keeps a factor the policy did not need, on a real any_of login', function (): void {
    /*
     * THE discriminator for the decision above, and the only test here where
     * the two candidate sets differ. Verified reachable against the real flow
     * before being frozen: the branch order makes depth-first satisfy [totp]
     * alone, so the verdict selects one factor while the attempt satisfied two.
     *
     * An implementation that persists the verdict's set stores [totp] and
     * derives aal1. This requires [password, totp] and aal2 -- the user
     * presented two distinct credentials and the record must say so.
     */
    proofPolicy(['any_of' => [['all_of' => ['totp']], ['all_of' => ['password', 'totp']]]]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $handle = proofIdentified();
    expect(proofSubmit($handle, ['password' => 'correct horse battery staple']))->toBeInstanceOf(Continuing::class);
    $result = proofSubmit($handle, ['code' => proofTotpCode()]);
    assert($result instanceof Authenticated);

    session()->start();
    app(SessionLifecycle::class)->establish($result->success);

    $session = \Fissible\Vouch\Models\AuthSession::query()->firstOrFail();
    $evidence = SessionEvidence::for($session);

    expect(array_map(static fn ($f): string => $f->factorId, $result->success->factors))
        ->toEqualCanonicalizing(['password', 'totp'])
        ->and(array_map(static fn ($f): string => $f->factorId, $evidence->factors))
        ->toEqualCanonicalizing(['password', 'totp'])
        ->and($evidence->derivedAcr())->toBe('aal2')
        ->and($session->acr)->toBe('aal2')
        // amr, acr and the proof are three views of ONE set. Listing a method
        // in amr that the proof omits would make the two disagree about what
        // happened.
        ->and($session->amr)->toEqualCanonicalizing(['password', 'totp']);
});

it('records a single-factor login as aal1', function (): void {
    /*
     * The other half of the regression pair. Together with the any_of test
     * above: password + totp persists BOTH and derives aal2, totp alone derives
     * aal1. Without this half, an implementation that simply hard-coded aal2
     * would satisfy the first test.
     *
     * Expressed with a totp-only policy rather than by submitting totp alone to
     * the any_of policy, because that is not reachable: the flow drives factor
     * order, and offering totp first there is refused with "That credential was
     * not accepted." Verified against the real flow rather than assumed.
     */
    proofPolicy(['all_of' => ['totp']]);
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $handle = proofIdentified();
    $result = proofSubmit($handle, ['code' => proofTotpCode()]);
    assert($result instanceof Authenticated);

    session()->start();
    app(SessionLifecycle::class)->establish($result->success);

    $session = \Fissible\Vouch\Models\AuthSession::query()->firstOrFail();

    expect(array_map(static fn ($f): string => $f->factorId, SessionEvidence::for($session)->factors))
        ->toBe(['totp'])
        ->and(SessionEvidence::for($session)->derivedAcr())->toBe('aal1')
        ->and($session->acr)->toBe('aal1');
});
