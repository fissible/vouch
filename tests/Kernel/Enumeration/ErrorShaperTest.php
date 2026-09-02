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

    expect($unknown)->toEqual($known);
});

it('shapes a screen that carries no retry policy at all', function (): void {
    /*
     * strictRetry() reads `$retry?->retryAfter`, and every other fixture in
     * this file supplies a policy -- so nothing here has ever entered that
     * method with null, and the null-safe operator was never load-bearing in
     * any Kernel test. An integration test elsewhere in the suite does reach
     * it, which is exactly how the gap stayed invisible: the mutation gate drew
     * its covering tests from the whole suite, so a Kernel guard was being held
     * up by an HTTP test.
     *
     * A screen with no retry state is ordinary, not exotic: the first request
     * of an attempt has nothing to report yet.
     */
    $shaped = (new ErrorShaper())->shape(
        new ScreenSpec(
            step: AuthStep::Identify,
            offeredFactors: [],
            fields: [new FieldSpec('identifier', 'email', 'username', maxLength: null)],
            challengePayload: null,
            errors: [],
            retry: null,
        ),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Strict,
    );

    expect($shaped->retry)->toBeNull();
});

it('withholds retry state under strict posture', function (): void {
    $shaped = (new ErrorShaper())->shape(
        identifyScreen(),
        Outcome::IdentifierUnknown,
        EnumerationPosture::Strict,
    );

    expect($shaped->retry)->toBeNull();
});

it('preserves a measured retry deadline while redacting ordinary strict state', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:30Z');
    $lockedUntil = new DateTimeImmutable('2026-08-16T12:15:00Z');
    $screen = identifyScreen();
    $screen = new ScreenSpec(
        step: $screen->step,
        offeredFactors: $screen->offeredFactors,
        fields: $screen->fields,
        challengePayload: $screen->challengePayload,
        errors: $screen->errors,
        retry: new RetryPolicy(
            attemptsRemaining: 3,
            lockedUntil: $lockedUntil,
            retryAfter: $retryAfter,
        ),
    );

    $shaped = (new ErrorShaper())->shape(
        $screen,
        Outcome::IdentifierUnknown,
        EnumerationPosture::Strict,
    );

    expect($shaped->retry)->not->toBeNull()
        ->and($shaped->retry?->attemptsRemaining)->toBeNull()
        ->and($shaped->retry?->lockedUntil)->toBeNull()
        ->and($shaped->retry?->retryAfter)->toBe($retryAfter);
});

it('shapes identical measured retry deadlines for known and unknown identifiers', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:30Z');
    $retry = new RetryPolicy(attemptsRemaining: 2, lockedUntil: null, retryAfter: $retryAfter);
    $base = identifyScreen();
    $screen = new ScreenSpec(
        step: $base->step,
        offeredFactors: $base->offeredFactors,
        fields: $base->fields,
        challengePayload: $base->challengePayload,
        errors: $base->errors,
        retry: $retry,
    );
    $shaper = new ErrorShaper();

    $known = $shaper->shape($screen, Outcome::IdentifierKnown, EnumerationPosture::Strict);
    $unknown = $shaper->shape($screen, Outcome::IdentifierUnknown, EnumerationPosture::Strict);

    expect($known)->toEqual($unknown)
        ->and($known->retry?->retryAfter)->toBe($retryAfter);
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

it('keeps every posture-permitted retry field under friendly posture', function (): void {
    $lockedUntil = new DateTimeImmutable('2026-08-16T12:15:00Z');
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:30Z');
    $base = identifyScreen();
    $screen = new ScreenSpec(
        step: $base->step,
        offeredFactors: $base->offeredFactors,
        fields: $base->fields,
        challengePayload: $base->challengePayload,
        errors: $base->errors,
        retry: new RetryPolicy(2, $lockedUntil, $retryAfter),
    );

    $shaped = (new ErrorShaper())->shape(
        $screen,
        Outcome::Locked,
        EnumerationPosture::Friendly,
    );

    expect($shaped->retry?->attemptsRemaining)->toBe(2)
        ->and($shaped->retry?->lockedUntil)->toBe($lockedUntil)
        ->and($shaped->retry?->retryAfter)->toBe($retryAfter);
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

it('does not fabricate a retry policy when a strict lock has no measured retry', function (): void {
    $base = identifyScreen();
    $screen = new ScreenSpec(
        step: $base->step,
        offeredFactors: $base->offeredFactors,
        fields: $base->fields,
        challengePayload: $base->challengePayload,
        errors: $base->errors,
        retry: null,
    );

    $shaped = (new ErrorShaper())->shape($screen, Outcome::Locked, EnumerationPosture::Strict);

    expect($shaped->retry)->toBeNull();
});

it('preserves a lock deadline but redacts its counter under strict posture', function (): void {
    $lockedUntil = new DateTimeImmutable('2026-08-16T12:15:00Z');
    $base = identifyScreen();
    $screen = new ScreenSpec(
        step: $base->step,
        offeredFactors: $base->offeredFactors,
        fields: $base->fields,
        challengePayload: $base->challengePayload,
        errors: $base->errors,
        retry: new RetryPolicy(0, $lockedUntil),
    );
    $shaped = (new ErrorShaper())->shape(
        $screen,
        Outcome::Locked,
        EnumerationPosture::Strict,
    );

    expect($shaped->retry)->not->toBeNull()
        ->and($shaped->retry?->attemptsRemaining)->toBeNull()
        ->and($shaped->retry?->lockedUntil)->toBe($lockedUntil);
});

it('preserves the complete measured lock policy under strict posture', function (): void {
    $lockedUntil = new DateTimeImmutable('2026-08-16T12:15:00Z');
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:30Z');
    $base = identifyScreen();
    $screen = new ScreenSpec(
        step: $base->step,
        offeredFactors: $base->offeredFactors,
        fields: $base->fields,
        challengePayload: $base->challengePayload,
        errors: $base->errors,
        retry: new RetryPolicy(0, $lockedUntil, $retryAfter),
    );

    $shaped = (new ErrorShaper())->shape($screen, Outcome::Locked, EnumerationPosture::Strict);

    expect($shaped->retry?->attemptsRemaining)->toBeNull()
        ->and($shaped->retry?->lockedUntil)->toBe($lockedUntil)
        ->and($shaped->retry?->retryAfter)->toBe($retryAfter);
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
