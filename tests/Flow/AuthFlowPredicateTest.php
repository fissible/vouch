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

    /*
     * The isDefault FLAG, not membership of the list.
     *
     * offeredFactors() maps over the WHOLE registry, marking one entry default,
     * so every screen contains every driver and `toContain('totp')` is true
     * whichever factor is presented. The first version of this asserted exactly
     * that and passed with the presentation hard-coded to 'password' -- the same
     * containment mistake already made once on defaultFactorFor(), caught the
     * same way, by probing rather than by reading.
     */
    $default = array_values(array_filter(
        $refused->screen->offeredFactors,
        static fn (\Fissible\Vouch\Kernel\Screen\FactorOption $o): bool => $o->isDefault,
    ));

    expect($default)->toHaveCount(1)
        ->and($default[0]->factorId)->toBe('totp');
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

it('defaults the attempt version to the CAS epoch at the schema level', function (): void {
    /*
     * The contract that makes AuthFlow's explicit `'version' => 1` a documented
     * redundancy rather than the only thing establishing the CAS epoch.
     *
     * The mutation that removes that array item survives, and it SHOULD: the
     * column carries `default(1)`, which compiles to `default '1'` on MySQL,
     * Postgres and SQLite alike, so removing the key changes nothing under the
     * current schema. That is schema-conditional equivalence, not a gap -- and
     * this test is what keeps the condition true.
     *
     * Inserting without the column is the point: it reads the DATABASE default
     * rather than anything the application supplied. If a later migration drops
     * or changes it, the equivalence silently becomes a real defect, and this
     * fails instead.
     */
    $id = \Illuminate\Support\Facades\DB::table('auth_attempts')->insertGetId([
        'handle' => bin2hex(random_bytes(32)),
        'state' => \Fissible\Vouch\Kernel\Attempt\AttemptState::Initiated->value,
        'bound_context' => str_repeat('a', 64),
        'expires_at' => now()->addMinutes(10),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(\Illuminate\Support\Facades\DB::table('auth_attempts')->where('id', $id)->value('version'))
        ->toEqual(1);
});

it('will not satisfy a policy with a recovery code offered as an ordinary factor', function (): void {
    /*
     * offeredFactorsFor()'s guard chain is a disjunction: a credential type is
     * skipped if ANY of "not a string", "is recovery_code", "not registered", or
     * "already satisfied" holds. Read as a conjunction it must satisfy ALL of
     * them to be skipped -- which no real type does, so recovery_code becomes
     * offered and therefore selectable.
     *
     * That is the failure this test exists for, and it needs a VALID recovery
     * code to see it. Submitting a wrong code refuses under either reading, so
     * an earlier version of this case -- factor=recovery_code carrying a TOTP
     * code -- passed with the guard inverted and proved nothing.
     *
     * Recovery evidence must never satisfy a login policy through the ordinary
     * path. It has its own action and its own outcome, and the whole point of
     * FactorStrength::Recovery is that a printed code buys a constrained
     * capability rather than a session.
     */
    predicatePolicy();
    AuthIdentifier::create([
        'user_id' => 7, 'type' => 'email', 'value' => 'ada@acme.example', 'verified_at' => now(),
    ]);
    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(7, ['password' => 'correct horse battery staple']);

    $codes = array_map(
        static fn (\Fissible\Vouch\Secrets\OneTimeSecret $secret): string => $secret->reveal(),
        app(\Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor::class)->enroll(7, [])->secrets,
    );

    $begun = predicateFlow()->advance(new FlowRequest(null, 'begin', [], predicateBinding()));
    assert($begun instanceof Continuing && is_string($begun->handle));

    predicateFlow()->advance(
        new FlowRequest($begun->handle, 'submit', ['identifier' => 'ada@acme.example'], predicateBinding()),
    );

    // A genuine recovery code, named as an ordinary factor on the submit action.
    $result = predicateFlow()->advance(new FlowRequest(
        $begun->handle,
        'submit',
        ['factor' => 'recovery_code', 'code' => $codes[0]],
        predicateBinding(),
    ));

    expect($result)->not->toBeInstanceOf(\Fissible\Vouch\Flow\Authenticated::class)
        // And not spent either: a code refused for being offered through the
        // wrong door must still work through the right one.
        ->and(AuthCredential::where('user_id', 7)->where('type', 'recovery_code')
            ->whereNull('disabled_at')->count())->toBe(10);
});
