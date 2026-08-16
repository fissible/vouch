<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\ScreenBuilder;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * ScreenBuilder is the one class whose output IS user-visible, so its
 * concatenations start as user-visible and have to be proven otherwise.
 *
 * They are proven otherwise: the only concatenation carrying survivors builds a
 * LogicException that is THROWN, and a thrown message never becomes a screen.
 * What a user actually reads is the `errors` array, and that is produced by
 * ErrorShaper from an Outcome -- a different mechanism, asserted here to be
 * populated without any of the exception's text.
 */

it('throws on a lock outcome without measured identifier state rather than rendering it', function (): void {
    /*
     * The audience proof. Outcome::Locked can be shaped only alongside the
     * measured identifier state that makes the disclosure truthful.
     *
     * Because it THROWS, the message reaches a stack trace and never a response
     * body. That is what makes its 15 concatenation mutants developer-facing.
     */
    expect(fn (): mixed => app(ScreenBuilder::class)->refused(
        AuthStep::Challenge,
        Outcome::Locked,
        EnumerationPosture::Friendly,
        'password',
    ))->toThrow(LogicException::class, 'requires Outcome::Locked and a measured identifier lock');
});

it('sources what the user reads from the shaper, not from builder text', function (): void {
    /*
     * A refusal a user CAN see. Its errors are non-empty under friendly posture
     * and carry none of the builder's own prose, so the two audiences are
     * genuinely separate rather than separated by convention.
     */
    $screen = app(ScreenBuilder::class)->refused(
        AuthStep::Challenge,
        Outcome::CredentialRejected,
        EnumerationPosture::Friendly,
        'password',
    );

    expect($screen->errors)->not->toBeEmpty();

    foreach ($screen->errors as $error) {
        expect((string) $error)->not->toContain('ScreenBuilder')
            ->and((string) $error)->not->toContain('measured identifier lock');
    }
});

it('discloses nothing under a strict posture', function (): void {
    // The same refusal with the posture that must not confirm anything.
    $screen = app(ScreenBuilder::class)->refused(
        AuthStep::Challenge,
        Outcome::CredentialRejected,
        EnumerationPosture::Strict,
        'password',
    );

    expect($screen->step)->toBe(AuthStep::Challenge);
});
