<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\ErrorShaper;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

function identifyScreen(): ScreenSpec
{
    return new ScreenSpec(
        step: AuthStep::Identify,
        offeredFactors: [],
        fields: [new FieldSpec('identifier', 'email', 'username', maxLength: null)],
        challengePayload: null,
        errors: [],
        retry: new RetryPolicy(attemptsRemaining: 3, lockedUntil: null),
    );
}

it('produces identical output for known and unknown identifiers under strict posture', function (): void {
    $shaper = new ErrorShaper();

    $known = $shaper->shape(identifyScreen(), Outcome::IdentifierKnown, EnumerationPosture::Strict);
    $unknown = $shaper->shape(identifyScreen(), Outcome::IdentifierUnknown, EnumerationPosture::Strict);

    expect($unknown->errors)->toBe($known->errors)
        ->and($unknown->step)->toBe($known->step)
        ->and($unknown->fields)->toEqual($known->fields);
});

it('withholds retry state under strict posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Strict,
    );

    expect($shaped->retry)->toBeNull();
});

it('discloses that an account does not exist under friendly posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Friendly,
    );

    expect($shaped->errors)->toBe(['No account matches that identifier.']);
});

it('keeps retry state under friendly posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Friendly,
    );

    expect($shaped->retry?->attemptsRemaining)->toBe(3);
});

it('gives the same message for a bad credential and an unknown identifier under strict posture', function (): void {
    $shaper = new ErrorShaper();

    $bad = $shaper->shape(identifyScreen(), Outcome::CredentialRejected, EnumerationPosture::Strict);
    $unknown = $shaper->shape(identifyScreen(), Outcome::IdentifierUnknown, EnumerationPosture::Strict);

    expect($bad->errors)->toBe($unknown->errors);
});

it('always discloses a lockout, because withholding it is useless and hostile', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::Locked,
        EnumerationPosture::Strict,
    );

    expect($shaped->errors)->toBe(['Too many attempts. Try again later.']);
});

it('discloses the uniform message under strict posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Strict,
    );

    expect($shaped->errors)->toBe(['Check your email to continue.']);
});

it('discloses that a credential was rejected under friendly posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::CredentialRejected,
        EnumerationPosture::Friendly,
    );

    expect($shaped->errors)->toBe(['That credential was not accepted.']);
});
