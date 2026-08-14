<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\ScreenBuilder;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * The field specs every screen hands to a client. Nothing asserted them, and
 * they are not decoration:
 *
 * - `autocomplete` is what tells a password manager which credential to offer.
 *   Wrong or missing, a manager fills the wrong field or nothing at all, and the
 *   user's fallback is to type a secret by hand or reuse one they remember.
 * - `maxLength` is the client-side input bound. Silently shortened, a long
 *   passphrase is truncated at the keyboard -- an authentication failure the
 *   user cannot see the cause of.
 * - `name` is the key the flow reads back out of the submission. Change it and
 *   the field arrives under a name nothing looks for, which the driver reports
 *   as a malformed credential.
 *
 * Asserted as complete tuples rather than field-by-field, because the failure
 * mode is one attribute drifting while the others stay right.
 */

/** @return array<int, array{string, string, string, ?int}> */
function fieldTuples(ScreenBuilder $builder, string $screen): array
{
    $spec = match ($screen) {
        'identify' => $builder->identify(EnumerationPosture::Friendly),
        'challenge' => $builder->challenge('totp', EnumerationPosture::Friendly),
        'refused-identify' => $builder->refused(AuthStep::Identify, Outcome::CredentialRejected, EnumerationPosture::Friendly),
        'refused-challenge' => $builder->refused(AuthStep::Challenge, Outcome::CredentialRejected, EnumerationPosture::Friendly, 'totp'),
        default => throw new InvalidArgumentException('Unknown screen: ' . $screen),
    };

    return array_map(
        static fn (FieldSpec $field): array => [$field->name, $field->type, $field->autocomplete, $field->maxLength],
        $spec->fields,
    );
}

it('offers the identifier field on the identify screen', function (): void {
    expect(fieldTuples(app(ScreenBuilder::class), 'identify'))
        ->toBe([['identifier', 'text', 'username', 255]]);
});

it('offers the code field on a challenge screen', function (): void {
    // one-time-code is what makes an OS surface a texted or authenticator code
    // for autofill; without it the user retypes it from another app.
    expect(fieldTuples(app(ScreenBuilder::class), 'challenge'))
        ->toBe([['code', 'text', 'one-time-code', 64]]);
});

it('keeps a refusal screen on the same step it refused', function (): void {
    /*
     * A refusal must re-present the step the user was on. Swap the branches and
     * a rejected identifier comes back asking for a code the user was never
     * issued -- a dead end that reads as the system being broken rather than the
     * credential being wrong.
     */
    $builder = app(ScreenBuilder::class);

    expect(fieldTuples($builder, 'refused-identify'))
        ->toBe([['identifier', 'text', 'username', 255]])
        ->and(fieldTuples($builder, 'refused-challenge'))
        ->toBe([['code', 'text', 'one-time-code', 64]]);
});
