<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * revoke() had no coverage on any driver: RemoveMethodCall on its single
 * `$credential->update(['disabled_at' => …])` survived, which means nothing
 * asserted that revoking disables anything.
 *
 * It is part of the Factor contract, so a host calling it to kill a compromised
 * credential would get a silent no-op -- the credential keeps authenticating and
 * the caller has every reason to believe it does not. Asserted across EVERY
 * registered driver rather than one, because the contract belongs to the
 * interface and each driver implements it separately.
 */

it('disables the credential it is asked to revoke', function (): void {
    $drivers = app(FactorRegistry::class)->all();

    expect($drivers)->not->toBeEmpty();

    foreach ($drivers as $driver) {
        expect($driver)->toBeInstanceOf(Factor::class);

        $credential = AuthCredential::create([
            'user_id' => 7,
            'type' => $driver->id(),
            'secret' => 'seed',
            'strength' => 'possession',
        ]);

        $driver->revoke($credential);

        expect($credential->refresh()->disabled_at)
            ->not->toBeNull("{$driver->id()} did not disable the credential");
    }
});

it('leaves other credentials alone when revoking one', function (): void {
    // The update is targeted at one row. Without the model's own key scoping it,
    // a revoke would disable every credential of that user.
    $driver = app(FactorRegistry::class)->all()[0];

    $target = AuthCredential::create([
        'user_id' => 7, 'type' => $driver->id(), 'secret' => 'a', 'strength' => 'possession',
    ]);
    $other = AuthCredential::create([
        'user_id' => 7, 'type' => $driver->id(), 'secret' => 'b', 'strength' => 'possession',
    ]);

    $driver->revoke($target);

    expect($target->refresh()->disabled_at)->not->toBeNull()
        ->and($other->refresh()->disabled_at)->toBeNull();
});

it('makes a revoked credential unusable for authentication, not merely flagged', function (): void {
    /*
     * The write is not the contract; unusability is. A reloaded disabled_at
     * proves the column changed -- this proves the credential has left the
     * authentication path, which is what "revoked" has to mean.
     *
     * Both directions are asserted because they are separate mechanisms: the
     * driver's own lookup filters on disabled_at, and the flow's offer set is
     * built by a different query. A credential could plausibly disappear from
     * one and not the other, and either alone would leave a revoked credential
     * still reachable.
     */
    $password = app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class);
    $password->enroll(7, ['password' => 'correct horse battery staple']);

    \Fissible\Vouch\Models\AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['all_of' => ['password']], 'posture' => 'friendly',
    ]);
    \Fissible\Vouch\Models\AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);

    $attempt = \Fissible\Vouch\Models\AuthAttempt::create([
        'handle' => bin2hex(random_bytes(32)),
        'state' => \Fissible\Vouch\Kernel\Attempt\AttemptState::FactorPending,
        'user_id' => 7,
        'bound_context' => str_repeat('v', 64),
        'expires_at' => now()->addMinutes(10),
    ]);

    // Sanity: the correct password verifies BEFORE revocation. Without this the
    // assertions below would pass against a fixture that never worked.
    $before = $password->verify(new \Fissible\Vouch\Factors\VerificationRequest(
        $attempt,
        ['password' => 'correct horse battery staple'],
    ));

    expect($before->failure)->toBeNull();

    $password->revoke(AuthCredential::where('user_id', 7)->where('type', 'password')->firstOrFail());

    // 1. The driver no longer finds a credential to verify against.
    $after = $password->verify(new \Fissible\Vouch\Factors\VerificationRequest(
        $attempt,
        ['password' => 'correct horse battery staple'],
    ));

    expect($after->failure)->toBe(\Fissible\Vouch\Factors\FactorFailure::NoCredential);

    // 2. And the flow stops offering it.
    $begun = app(\Fissible\Vouch\Flow\AuthFlow::class)->advance(new \Fissible\Vouch\Flow\FlowRequest(
        null, 'begin', [], \Fissible\Vouch\Sessions\SessionBinding::for('revoke-flow', \Fissible\Vouch\Sessions\BindingDomain::Attempt),
    ));
    assert($begun instanceof \Fissible\Vouch\Flow\Continuing && is_string($begun->handle));

    $next = app(\Fissible\Vouch\Flow\AuthFlow::class)->advance(new \Fissible\Vouch\Flow\FlowRequest(
        $begun->handle, 'submit', ['identifier' => 'ada@acme.example'],
        \Fissible\Vouch\Sessions\SessionBinding::for('revoke-flow', \Fissible\Vouch\Sessions\BindingDomain::Attempt),
    ));
    assert($next instanceof \Fissible\Vouch\Flow\Continuing);

    $submitted = app(\Fissible\Vouch\Flow\AuthFlow::class)->advance(new \Fissible\Vouch\Flow\FlowRequest(
        $begun->handle, 'submit', ['password' => 'correct horse battery staple'],
        \Fissible\Vouch\Sessions\SessionBinding::for('revoke-flow', \Fissible\Vouch\Sessions\BindingDomain::Attempt),
    ));

    expect($submitted)->not->toBeInstanceOf(\Fissible\Vouch\Flow\Authenticated::class);
});
