<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthPolicy;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * The predicates left in AuthFlow after the rehydration work. Re-enumerated
 * against current source rather than followed from earlier notes -- the file
 * moved when selectFactor() and the date guard went in, so the old line numbers
 * pointed at unrelated code.
 */

function predicateBinding(): string
{
    return \Fissible\Vouch\Sessions\SessionBinding::for(
        'predicate-session',
        \Fissible\Vouch\Sessions\BindingDomain::Attempt,
    );
}

function predicateFlow(): \Fissible\Vouch\Flow\AuthFlow
{
    return app(\Fissible\Vouch\Flow\AuthFlow::class);
}

function predicatePolicy(): void
{
    AuthPolicy::create([
        'tenant_id' => null, 'scope' => 'login',
        'document' => ['any_of' => ['password', 'totp']], 'posture' => 'friendly',
    ]);
}

it('starts an attempt at version 1 so the first compare-and-swap has a baseline', function (): void {
    /*
     * Every transition is a compare-and-swap on this column. Starting anywhere
     * but 1 -- or omitting it and inheriting whatever the column defaults to --
     * decouples the counter from what the store expects to find, and a CAS that
     * cannot match is a transition that silently refuses.
     */
    predicateFlow()->advance(new FlowRequest(null, 'begin', [], predicateBinding()));

    expect(AuthAttempt::query()->latest('id')->firstOrFail()->version)->toBe(1);
});

it('refuses an identifier that is absent or blank without advancing', function (mixed $submitted): void {
    /*
     * `$value === null || $value === ''`. Read as AND, a blank submission passes
     * the guard and is looked up as an identifier -- and an empty string is not a
     * value any user owns, so the flow would advance an attempt on evidence
     * nobody supplied.
     */
    predicatePolicy();
    $begun = predicateFlow()->advance(new FlowRequest(null, 'begin', [], predicateBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    $input = $submitted === '__absent__' ? [] : ['identifier' => $submitted];
    $result = predicateFlow()->advance(new FlowRequest($begun->handle, 'submit', $input, predicateBinding()));
    // Narrowed by a real check, not a cast: the step assertion below reads a
    // property only Continuing has.
    assert($result instanceof Continuing);

    expect($result)->toBeInstanceOf(Continuing::class)
        // Still on the identify step, and no identifier recorded.
        ->and($result->screen->step)->toBe(\Fissible\Vouch\Kernel\Screen\AuthStep::Identify)
        ->and(AuthAttempt::where('handle', $begun->handle)->firstOrFail()->identifier)->toBeNull();
})->with(['absent' => ['__absent__'], 'empty string' => ['']]);

it('records the identifier it was given alongside the resolved user', function (): void {
    /*
     * Both keys of the same update. The user_id is load-bearing everywhere; the
     * identifier is the only record of WHAT was submitted, which is what an
     * audit trail reads and what a later step re-presents.
     */
    predicatePolicy();
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);

    $begun = predicateFlow()->advance(new FlowRequest(null, 'begin', [], predicateBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    predicateFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], predicateBinding()),
    );

    $attempt = AuthAttempt::where('handle', $begun->handle)->firstOrFail();

    expect($attempt->identifier)->toBe('ada@acme.example')
        ->and($attempt->user_id)->toBe(7);
});

it('presents a refusal against a factor the user actually holds', function (): void {
    /*
     * `$offered[0] ?? 'password'`. A user enrolled only in TOTP must not be
     * refused on a password screen -- that both misdescribes the credential they
     * were asked for and, over repeated attempts, distinguishes users by which
     * screen their refusal comes back on.
     */
    predicatePolicy();
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    AuthCredential::create(['user_id' => 7, 'type' => 'totp', 'secret' => 'seed', 'strength' => 'possession']);

    $begun = predicateFlow()->advance(new FlowRequest(null, 'begin', [], predicateBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    predicateFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], predicateBinding()),
    );

    $refused = predicateFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['code' => '000000'], predicateBinding()),
    );
    assert($refused instanceof Continuing);

    $offered = array_map(
        static fn (\Fissible\Vouch\Kernel\Screen\FactorOption $o): string => $o->factorId,
        $refused->screen->offeredFactors,
    );

    expect($offered)->toContain('totp');
});

it('treats a blank factor selection as no selection, not as a factor named ""', function (): void {
    /*
     * `$requested !== null && $requested !== ''`. A form that posts an empty
     * factor field must fall through to the server's default, not be read as a
     * selection of a factor called "" -- which is offered by nothing and would
     * refuse every such submission.
     */
    predicatePolicy();
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);

    $begun = predicateFlow()->advance(new FlowRequest(null, 'begin', [], predicateBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    predicateFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], predicateBinding()),
    );

    $result = predicateFlow()->advance(new FlowRequest(
        $begun->handle,
        'submit',
        ['factor' => '', 'password' => 'correct horse battery staple'],
        predicateBinding(),
    ));

    expect($result)->toBeInstanceOf(\Fissible\Vouch\Flow\Authenticated::class);
});

it('offers nothing when the identifier resolved to no user', function (): void {
    /*
     * offeredFactorsFor() returns early on a null user. Without that return the
     * credential query runs with user_id = null, and any row that happened to
     * match would be offered as though it belonged to the unknown identifier.
     */
    predicatePolicy();

    $begun = predicateFlow()->advance(new FlowRequest(null, 'begin', [], predicateBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    predicateFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'nobody@acme.example'], predicateBinding()),
    );

    $result = predicateFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['password' => 'anything'], predicateBinding()),
    );

    expect($result)->toBeInstanceOf(Continuing::class)
        ->and($result)->not->toBeInstanceOf(\Fissible\Vouch\Flow\Authenticated::class);
});
