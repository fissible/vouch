<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\ScreenBuilder;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;

function screenBuilder(): ScreenBuilder
{
    return app(ScreenBuilder::class);
}

it('offers an identifier field on the identify screen', function (): void {
    $screen = screenBuilder()->identify(EnumerationPosture::Friendly);

    expect($screen->step)->toBe(AuthStep::Identify)
        ->and($screen->fields)->toHaveCount(1)
        ->and($screen->fields[0])->toBeInstanceOf(FieldSpec::class)
        ->and($screen->fields[0]->name)->toBe('identifier')
        ->and($screen->errors)->toBe([])
        ->and($screen->retry)->toBeNull();
});

it('offers every registered factor on a challenge screen', function (): void {
    $screen = screenBuilder()->challenge('password', EnumerationPosture::Friendly);

    expect($screen->step)->toBe(AuthStep::Challenge)
        ->and($screen->offeredFactors)->not->toBeEmpty()
        ->and($screen->offeredFactors[0])->toBeInstanceOf(FactorOption::class);
});

it('marks exactly one offered factor as the default', function (): void {
    // A screen with two defaults, or none, is a rendering ambiguity every
    // adapter would resolve differently.
    $defaults = array_filter(
        screenBuilder()->challenge('password', EnumerationPosture::Friendly)->offeredFactors,
        static fn (FactorOption $option): bool => $option->isDefault,
    );

    expect($defaults)->toHaveCount(1);
});

it('never discloses which of the two identifier outcomes occurred under strict posture', function (): void {
    /*
     * The enumeration boundary. Under strict posture an unknown identifier and
     * a rejected credential must be indistinguishable in the rendered screen,
     * exactly as they are indistinguishable in the HTTP status.
     */
    $unknown = screenBuilder()->refused(AuthStep::Identify, Outcome::IdentifierUnknown, EnumerationPosture::Strict);
    $rejected = screenBuilder()->refused(AuthStep::Identify, Outcome::CredentialRejected, EnumerationPosture::Strict);

    expect($unknown->errors)->toBe($rejected->errors);
});

it('does distinguish them under friendly posture', function (): void {
    // Proves the strict assertion above is measuring posture, not measuring a
    // builder that always returns the same message.
    $unknown = screenBuilder()->refused(AuthStep::Identify, Outcome::IdentifierUnknown, EnumerationPosture::Friendly);
    $rejected = screenBuilder()->refused(AuthStep::Identify, Outcome::CredentialRejected, EnumerationPosture::Friendly);

    expect($unknown->errors)->not->toBe($rejected->errors);
});

it('never emits a retry policy in 2.3', function (): void {
    // Rate limiting is 2.3b. A fabricated retry state would report something
    // nobody measured.
    foreach ([Outcome::IdentifierUnknown, Outcome::CredentialRejected] as $outcome) {
        expect(screenBuilder()->refused(AuthStep::Challenge, $outcome, EnumerationPosture::Strict)->retry)
            ->toBeNull();
    }
});

it('refuses to shape a locked outcome', function (): void {
    /*
     * ErrorShaper discloses Locked in full under every posture, which is safe
     * only when rate limits apply identically to known and unknown identifiers.
     * 2.3 has no rate limiting, so nothing can honestly be locked -- and a
     * Locked screen with a null RetryPolicy would be a fabricated lockout.
     * 2.3b removes this guard when it can satisfy the precondition.
     */
    screenBuilder()->refused(AuthStep::Challenge, Outcome::Locked, EnumerationPosture::Strict);
})->throws(LogicException::class);
