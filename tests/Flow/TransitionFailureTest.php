<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\AttemptStore;
use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Tests\Support\TransitionSelectiveStore;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * What the flow does when a compare-and-swap LOSES.
 *
 * A CAS loss means a concurrent request advanced the same attempt first. It is
 * an ordinary event, unreachable from a single-threaded test, and every branch
 * handling it was uncovered -- the last uncovered code in AuthFlow.
 *
 * The fixture fails one nominated transition and delegates the rest, so
 * everything before the failure is real and the attempt arrives at the boundary
 * in the state production would put it in. Failing the whole store would test a
 * database that had stopped answering, which is a different and less interesting
 * thing.
 */

function failureBinding(): string
{
    return SessionBinding::for('transition-failure-session', BindingDomain::Attempt);
}

function flowWithFailureAt(AttemptState $state): \Fissible\Vouch\Flow\AuthFlow
{
    $store = new TransitionSelectiveStore(app(AttemptStore::class), $state);
    app()->instance(AttemptStore::class, $store);
    app()->forgetInstance(\Fissible\Vouch\Flow\AuthFlow::class);

    return app(\Fissible\Vouch\Flow\AuthFlow::class);
}

function failureFixture(): void
{
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'friendly',
    ]);
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);
}

it('refuses rather than authenticating when the satisfy transition loses', function (): void {
    /*
     * The transition that records the factor as satisfied is also the one
     * carrying the driver's single-use mutations. If it loses and the flow
     * carried on, the attempt would report a factor it never recorded.
     */
    failureFixture();
    $flow = flowWithFailureAt(AttemptState::FactorSatisfied);

    $begun = $flow->advance(new FlowRequest(null, 'begin', [], failureBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    $flow->advance(new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], failureBinding()));

    $result = $flow->advance(
        new FlowRequest($begun->handle, 'submit', ['password' => 'correct horse battery staple'], failureBinding()),
    );

    $attempt = AuthAttempt::where('handle', $begun->handle)->firstOrFail();

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result)->not->toBeInstanceOf(Authenticated::class)
        // No evidence written: the ledger must not record a factor whose
        // transition did not commit.
        ->and($attempt->satisfied_factors)->toBeNull()
        ->and($attempt->state)->not->toBe(AttemptState::Authenticated);
});

it('does not attempt the authenticate transition after the satisfy one loses', function (): void {
    /*
     * The refusal must STOP the walk, not merely change what is returned. A flow
     * that pressed on to Authenticated after losing the satisfy CAS would be
     * issuing a session for evidence it failed to record -- which the returned
     * value alone cannot rule out, so this reads the store's call log.
     */
    failureFixture();
    $store = new TransitionSelectiveStore(app(AttemptStore::class), AttemptState::FactorSatisfied);
    app()->instance(AttemptStore::class, $store);
    app()->forgetInstance(\Fissible\Vouch\Flow\AuthFlow::class);
    $flow = app(\Fissible\Vouch\Flow\AuthFlow::class);

    $begun = $flow->advance(new FlowRequest(null, 'begin', [], failureBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    $flow->advance(new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], failureBinding()));
    $flow->advance(new FlowRequest($begun->handle, 'submit', ['password' => 'correct horse battery staple'], failureBinding()));

    expect($store->attempted())->not->toContain(AttemptState::Authenticated);
});

it('leaves single-use evidence unspent when the transition carrying it loses', function (): void {
    /*
     * The strongest of these. A recovery code is burned by a mutation that rides
     * the satisfy transition precisely so a lost CAS rolls it back. If the code
     * were spent anyway, a user who lost a race would have paid a one-time code
     * for an authentication that never happened -- and with ten codes, a few
     * unlucky races is a locked-out account.
     */
    failureFixture();
    $codes = app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets;

    $flow = flowWithFailureAt(AttemptState::FactorSatisfied);

    $begun = $flow->advance(new FlowRequest(null, 'begin', [], failureBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    $flow->advance(new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], failureBinding()));

    $flow->advance(new FlowRequest(
        $begun->handle,
        'recover',
        ['code' => $codes[0]->reveal()],
        failureBinding(),
    ));

    expect(AuthCredential::where('user_id', 7)->where('type', 'recovery_code')
        ->whereNull('disabled_at')->count())->toBe(10);
});

it('refuses on the identify step when entering the challenge state loses', function (): void {
    /*
     * Identify performs two transitions together so the attempt never rests in a
     * state a later request must repair. Losing the second one has to refuse on
     * the identify step rather than present a challenge the attempt is not in a
     * state to accept.
     */
    failureFixture();
    $flow = flowWithFailureAt(AttemptState::FactorPending);

    $begun = $flow->advance(new FlowRequest(null, 'begin', [], failureBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    $result = $flow->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], failureBinding()),
    );
    assert($result instanceof Continuing);

    expect($result->screen->step)->toBe(\Fissible\Vouch\Kernel\Screen\AuthStep::Identify);
});
