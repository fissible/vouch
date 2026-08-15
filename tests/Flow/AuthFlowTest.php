<?php

declare(strict_types=1);

use Fissible\Vouch\Attempts\Mutations\SingleUseMutation;
use Fissible\Vouch\Attempts\TransitionOutcome;
use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

const FLOW_BINDING_SOURCE = 'host-session-under-test';

function flowBinding(): string
{
    return SessionBinding::for(FLOW_BINDING_SOURCE, BindingDomain::Attempt);
}

function theFlow(): AuthFlow
{
    return app(AuthFlow::class);
}

/**
 * @param  array<string, mixed>  $document
 */
function flowPolicy(array $document = ['all_of' => ['password']]): void
{
    AuthPolicy::create(['tenant_id' => null, 'scope' => 'login', 'document' => $document, 'posture' => 'friendly']);
}

function flowPassword(int $userId = 7, string $password = 'correct horse battery staple'): void
{
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll($userId, ['password' => $password]);
}

/**
 * @param  array<string, mixed>  $input
 */
function flowBegin(array $input = []): FlowRequest
{
    return new FlowRequest(null, 'begin', $input, flowBinding());
}

/**
 * @param  array<string, mixed>  $input
 */
function flowAdvance(string $handle, array $input, ?string $binding = null, string $action = 'submit'): FlowRequest
{
    return new FlowRequest($handle, $action, $input, $binding ?? flowBinding());
}

/** Begins an attempt and submits the identifier, returning the handle. */
function flowIdentified(int $userId = 7): string
{
    AuthIdentifier::create([
        'user_id' => $userId, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);

    $begun = theFlow()->advance(flowBegin());
    assert($begun instanceof Continuing);
    $handle = $begun->handle;
    assert(is_string($handle));
    theFlow()->advance(flowAdvance($handle, ['identifier' => 'ada@acme.example']));

    return $handle;
}

it('creates a persisted attempt and returns its handle', function (): void {
    $result = theFlow()->advance(flowBegin());
    // assert() for PHPStan narrowing before the property reads; the
    // toBeInstanceOf assertion below is the behavioural check.
    assert($result instanceof Continuing);

    $attempt = AuthAttempt::query()->latest('id')->firstOrFail();

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result->handle)->toBe($attempt->handle)
        ->and($attempt->state)->toBe(AttemptState::Initiated)
        ->and($attempt->handle)->toHaveLength(64)
        ->and($attempt->expires_at)->not->toBeNull()
        ->and($attempt->bound_context)->toBe(flowBinding())
        ->and($attempt->bound_context)->not->toContain(FLOW_BINDING_SOURCE);
});

it('issues a distinct handle per attempt', function (): void {
    // A guessable or reused handle plus a matching bound context is an attempt
    // takeover, so this pins that the handle comes from a CSPRNG per call.
    theFlow()->advance(flowBegin());
    theFlow()->advance(flowBegin());

    expect(AuthAttempt::query()->distinct()->count('handle'))->toBe(2);
});

it('echoes no handle when refusing an unknown one', function (): void {
    $result = theFlow()->advance(flowAdvance('not-a-real-handle', []));
    assert($result instanceof Continuing);

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result->handle)->toBeNull();
});

it('refuses to advance an attempt from a different bound context', function (): void {
    /*
     * The handle identifies the attempt; it must not also authorize it. This is
     * the test that makes ContextMismatch a security invariant rather than a
     * conditional one.
     */
    flowPolicy();
    flowPassword();

    $begun = theFlow()->advance(flowBegin());
    assert($begun instanceof Continuing);
    $handle = $begun->handle;
    assert(is_string($handle));

    $result = theFlow()->advance(flowAdvance(
        $handle,
        ['identifier' => 'ada@acme.example'],
        SessionBinding::for('a-different-host-session', BindingDomain::Attempt),
    ));
    assert($result instanceof Continuing);

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result->handle)->toBeNull();
});

it('authenticates when the policy is satisfied', function (): void {
    flowPolicy();
    flowPassword();

    $handle = flowIdentified();

    $result = theFlow()->advance(flowAdvance($handle, ['password' => 'correct horse battery staple']));
    assert($result instanceof Authenticated);

    expect($result)->toBeInstanceOf(Authenticated::class)
        ->and($result->success->userId)->toBe(7)
        ->and($result->success->amr())->toBe(['password'])
        ->and($result->success->boundContext)->toBe(flowBinding());
});

it('continues with the next factor when the policy is only partly satisfied', function (): void {
    /*
     * The other half of "authenticates when the policy is satisfied", and the
     * half nothing asserted: an `all_of` policy with one factor still
     * outstanding must come back as Continuing with the next challenge.
     *
     * Without this, deleting the `return new Continuing(...)` on the
     * not-yet-Authenticated branch leaves the whole suite green while a
     * half-authenticated attempt falls straight through into the Authenticated
     * transition below it. The outcome there depends on what the transition
     * rules allow, which is exactly the wrong thing for this decision to depend
     * on: whether a second factor is still required is the policy's call, not
     * the state machine's.
     */
    flowPolicy(['all_of' => ['password', 'totp']]);
    flowPassword();
    app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class)->enroll(7, ['label' => 'ada@acme.example']);

    $handle = flowIdentified();

    $result = theFlow()->advance(flowAdvance($handle, ['password' => 'correct horse battery staple']));

    expect($result)->toBeInstanceOf(Continuing::class);

    assert($result instanceof Continuing);

    /*
     * The class alone does NOT discriminate, and assuming it did is how this
     * test first failed to kill anything: the fall-through lands on $refusal(),
     * which also returns a Continuing carrying the same handle. The artifact
     * that distinguishes the two is the SCREEN — an offer of the next factor
     * carries no errors, whereas a refusal carries CredentialRejected.
     */
    expect($result->screen->errors)->toBe([])
        ->and($result->screen->step)->toBe(AuthStep::Challenge)
        // The handle must survive, or the client cannot present the second factor.
        ->and($result->handle)->toBe($handle);
});

/**
 * Swap in a store that DECLINES the given target state with the given outcome,
 * delegating every other transition to the real one.
 */
function declineTransition(AttemptState $declined, TransitionOutcome $outcome): void
{
    $inner = app(AttemptStore::class);

    app()->instance(AttemptStore::class, new class($inner, $declined, $outcome) implements AttemptStore
    {
        public function __construct(
            private readonly AttemptStore $inner,
            private readonly AttemptState $declined,
            private readonly TransitionOutcome $outcome,
        ) {}

        public function transition(
            AuthAttempt $attempt,
            AttemptState $to,
            SingleUseMutation ...$mutations,
        ): TransitionOutcome {
            if ($to === $this->declined) {
                return $this->outcome;
            }

            return $this->inner->transition($attempt, $to, ...$mutations);
        }
    });

    // AuthFlow is a singleton; drop any instance built over the real store.
    app()->forgetInstance(AuthFlow::class);
}

it('never returns Authenticated when the final transition is declined', function (TransitionOutcome $outcome): void {
    /*
     * The branch nothing reached, and the most dangerous one in this file.
     *
     * `transition()` returns an outcome; it does not throw. If the attempt loses
     * its compare-and-swap — a concurrent request advanced the same attempt, or
     * a single-use guard already fired — the store answers something other than
     * Succeeded and the flow must refuse. Delete that `return $refusal();` and
     * execution falls straight through to `return new Authenticated(...)`: the
     * caller is handed a full AuthSuccess for an attempt the store declined to
     * advance. Every earlier test stayed green, because none of them could make
     * the transition fail.
     *
     * Asserted over EVERY declined outcome, not just the one that found it. The
     * rule is "a declined transition terminates in a refusal", and a rule stated
     * for one enum case is a coincidence waiting to be relied on.
     *
     * Forced deterministically with a decorator rather than by racing: the real
     * store handles every step except the one under test.
     */
    declineTransition(AttemptState::Authenticated, $outcome);

    flowPolicy();
    flowPassword();

    $handle = flowIdentified();

    $result = theFlow()->advance(flowAdvance($handle, ['password' => 'correct horse battery staple']));

    expect($result)->not->toBeInstanceOf(Authenticated::class)
        ->and($result)->toBeInstanceOf(Continuing::class);

    assert($result instanceof Continuing);

    // The refusal screen, not an offer: the same discriminator the partial-policy
    // test uses, read the other way round.
    expect($result->screen->errors)->not->toBe([]);
})->with([
    'illegal transition' => [TransitionOutcome::IllegalTransition],
    'expired' => [TransitionOutcome::Expired],
    'context mismatch' => [TransitionOutcome::ContextMismatch],
    'challenge already consumed' => [TransitionOutcome::ChallengeAlreadyConsumed],
    'credential already consumed' => [TransitionOutcome::CredentialAlreadyConsumed],
    'timestep replay' => [TransitionOutcome::TimestepReplay],
    'concurrent modification' => [TransitionOutcome::ConcurrentModification],
]);

it('never returns Authenticated when any transition on the path is declined', function (AttemptState $declined): void {
    /*
     * The generalisation that stops this failure mode re-entering through a
     * different branch. `new Authenticated(...)` is constructed in exactly one
     * place, but it is reached through a chain of transitions — Identified,
     * FactorPending, FactorSatisfied, Authenticated — each guarded separately,
     * and one of those guards was missing its return for the whole of Phase 2.
     *
     * Declining any single link must end the request in a refusal. Asserting it
     * per link means a future guard that forgets to return fails here, rather
     * than waiting for someone to notice a fail-open in review.
     */
    declineTransition($declined, TransitionOutcome::ConcurrentModification);

    flowPolicy();
    flowPassword();

    $handle = flowIdentified();

    $result = theFlow()->advance(flowAdvance($handle, ['password' => 'correct horse battery staple']));

    expect($result)->not->toBeInstanceOf(Authenticated::class);
})->with([
    'identified' => [AttemptState::Identified],
    'factor pending' => [AttemptState::FactorPending],
    'factor satisfied' => [AttemptState::FactorSatisfied],
    'authenticated' => [AttemptState::Authenticated],
]);

it('does not rotate any session itself', function (): void {
    // AuthFlow is not session-aware. Authenticated carries the facts;
    // SessionLifecycle performs the rotation, after this returns.
    flowPolicy();
    flowPassword();

    $handle = flowIdentified();
    theFlow()->advance(flowAdvance($handle, ['password' => 'correct horse battery staple']));

    expect(AuthSession::count())->toBe(0);
});

it('opens recovery grace rather than authenticating on a recovery code', function (): void {
    /*
     * Recovery evidence is filtered out of satisfiability by the kernel, so the
     * policy is never satisfied by it. The flow must recognise that and open the
     * constrained capability instead of leaving the user stuck.
     */
    flowPolicy();
    flowPassword();
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $handle = flowIdentified();
    $result = theFlow()->advance(flowAdvance($handle, ['code' => $codes[0]], action: 'recover'));
    assert($result instanceof RecoveryGraceStarted);

    expect($result)->toBeInstanceOf(RecoveryGraceStarted::class)
        ->and($result->userId)->toBe(7);
});

it('burns a recovery code only through the store', function (): void {
    // The driver returns a DisableCredential mutation; the flow hands it to
    // transition(). If the flow burned it directly, a later transition failure
    // would leave the code spent and the user unauthenticated.
    flowPolicy();
    flowPassword();
    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $handle = flowIdentified();
    theFlow()->advance(flowAdvance($handle, ['code' => $codes[0]], action: 'recover'));

    expect(AuthCredential::where('type', 'recovery_code')->whereNull('disabled_at')->count())->toBe(9);
});
