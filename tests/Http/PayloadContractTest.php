<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthSuccess;
use Fissible\Vouch\Kernel\Assurance\AssuranceFacts;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Http\FlowResultSerializer;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * The JSON envelope is the package's published wire format, and nothing was
 * asserting its KEYS.
 *
 * Existing tests read individual values out of the payload, which proves those
 * keys are present and says nothing about the rest. Drop 'maxLength' from a
 * field, or 'isDefault' from an offered factor, and every one of them still
 * passes while every client silently loses an input constraint. A wire format is
 * defined by its complete key set, so that is what these assert -- exactly, and
 * in order, so an addition is as visible as a removal.
 *
 * These are contract tests. They are SUPPOSED to fail when the payload changes;
 * a failure here is the reminder to version the change, not a test to relax.
 */

function contractScreen(): ScreenSpec
{
    return new ScreenSpec(
        step: AuthStep::Challenge,
        offeredFactors: [new FactorOption('password', 'Password', FactorStrength::Knowledge, true)],
        fields: [new FieldSpec('password', 'password', 'current-password', 128)],
        challengePayload: null,
        errors: [],
        // Null until 2.3b brings rate limiting. The serializer emits the key
        // regardless, which is the subject of one of the tests below.
        retry: null,
    );
}

function contractSerializer(): FlowResultSerializer
{
    return new FlowResultSerializer();
}

it('serializes every result variant with the same envelope keys', function (): void {
    /*
     * The envelope shape must not vary by outcome. A client parses one structure
     * and reads `result` to discriminate; a variant that quietly omits a key
     * forces the client to branch before it can even find the discriminator.
     *
     * 'authenticated' additionally carries returnTo -- the one deliberate
     * difference, asserted rather than tolerated.
     */
    $screen = contractScreen();

    $continuing = contractSerializer()->toArray(new Continuing($screen, 'handle-1'));
    $grace = contractSerializer()->toArray(new RecoveryGraceStarted(7, str_repeat('f', 64), $screen));

    expect(array_keys($continuing))->toBe(['result', 'handle', 'screen'])
        ->and($continuing['result'])->toBe('continuing')
        ->and($continuing['handle'])->toBe('handle-1')
        ->and(array_keys($grace))->toBe(['result', 'handle', 'screen'])
        ->and($grace['result'])->toBe('recovery_grace')
        // Null, not the attempt handle: a recovery-grace response must not hand
        // back a credential-shaped token for an attempt that is over.
        ->and($grace['handle'])->toBeNull();
});

it('adds returnTo only to the authenticated envelope, and never echoes it back unvalidated', function (): void {
    /*
     * returnTo is the one key that varies by variant, and it is the only one in
     * the envelope that originates outside the package. It must appear on
     * 'authenticated' and nowhere else -- a redirect target attached to a
     * still-continuing attempt is an open-redirect handed out before
     * authentication finished.
     *
     * The serializer deliberately does NOT re-validate it; IntendedDestination
     * already did, and a second validator is a second place to drift. So what is
     * pinned here is placement, not sanitisation.
     */
    $screen = contractScreen();
    $success = new AuthSuccess(7, [], AssuranceFacts::fromFactors([]), 'aal1', str_repeat('f', 64));

    $authenticated = contractSerializer()->toArray(new Authenticated($success, $screen), '/dashboard');
    $continuing = contractSerializer()->toArray(new Continuing($screen, 'h'), '/dashboard');

    expect(array_keys($authenticated))->toBe(['result', 'handle', 'screen', 'returnTo'])
        ->and($authenticated['result'])->toBe('authenticated')
        ->and($authenticated['handle'])->toBeNull()
        ->and($authenticated['returnTo'])->toBe('/dashboard')
        // Same returnTo passed in, and it must not surface on a continuing flow.
        ->and($continuing)->not->toHaveKey('returnTo');
});

it('serializes the screen with its complete key set', function (): void {
    $payload = contractSerializer()->toArray(new Continuing(contractScreen(), 'h'));
    $screen = $payload['screen'];

    expect($screen)->toBeArray()
        ->and(array_keys((array) $screen))
        ->toBe(['step', 'offeredFactors', 'fields', 'challengePayload', 'errors', 'retry']);
});

it('serializes each offered factor and field with its complete key set', function (): void {
    /*
     * The nested shapes, which array_map() builds one entry at a time. Unwrap
     * the map and the client receives the value objects themselves; drop a key
     * and it receives an option it cannot render or a field it cannot validate.
     */
    $payload = contractSerializer()->toArray(new Continuing(contractScreen(), 'h'));
    $screen = (array) $payload['screen'];

    $offered = (array) $screen['offeredFactors'];
    $fields = (array) $screen['fields'];

    expect(array_keys((array) $offered[0]))->toBe(['factorId', 'label', 'strength', 'isDefault'])
        ->and(array_keys((array) $fields[0]))->toBe(['name', 'type', 'autocomplete', 'maxLength'])
        // The values too: a key present but empty is the same outage to a client.
        ->and(((array) $fields[0])['maxLength'])->toBe(128)
        ->and(((array) $offered[0])['isDefault'])->toBeTrue()
        ->and(((array) $offered[0])['strength'])->toBe('Knowledge');
});

it('reports retry as null rather than omitting it', function (): void {
    /*
     * Rate limiting lands in 2.3b. Until then the key must still be present and
     * null: a client that treats a missing key as "no retry state" and a null
     * key as "no retry state" behaves identically today and diverges the moment
     * the field becomes real. Present-and-null is the honest placeholder.
     */
    $screen = (array) contractSerializer()->toArray(new Continuing(contractScreen(), 'h'))['screen'];

    expect($screen)->toHaveKey('retry')
        ->and($screen['retry'])->toBeNull();
});
