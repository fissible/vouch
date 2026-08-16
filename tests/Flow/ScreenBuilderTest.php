<?php

declare(strict_types=1);

use Fissible\Vouch\Flow\ScreenBuilder;
use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\EnrollmentResult;
use Fissible\Vouch\Factors\FactorFailure;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Factors\FactorResult;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\SharedThrottle;

function screenBuilder(): ScreenBuilder
{
    return app(ScreenBuilder::class);
}

it('offers an identifier field on the identify screen', function (): void {
    $screen = screenBuilder()->identify(EnumerationPosture::Friendly);
    $factors = array_map(
        static fn (FactorOption $option): string => $option->factorId,
        $screen->offeredFactors,
    );
    $defaults = array_values(array_filter(
        $screen->offeredFactors,
        static fn (FactorOption $option): bool => $option->isDefault,
    ));

    expect($screen->step)->toBe(AuthStep::Identify)
        ->and($screen->fields)->toHaveCount(1)
        ->and($screen->fields[0])->toBeInstanceOf(FieldSpec::class)
        ->and($screen->fields[0]->name)->toBe('identifier')
        ->and($factors)->toBe(['password', 'totp', 'email_otp', 'sms_otp'])
        ->and($defaults)->toHaveCount(1)
        ->and($defaults[0]->factorId)->toBe('password')
        ->and($screen->errors)->toBe([])
        ->and($screen->retry)->toBeNull();
});

it('offers every registered factor on a challenge screen', function (): void {
    $screen = screenBuilder()->challenge('password', EnumerationPosture::Friendly);
    $factors = array_map(
        static fn (FactorOption $option): string => $option->factorId,
        $screen->offeredFactors,
    );

    expect($screen->step)->toBe(AuthStep::Challenge)
        ->and($factors)->toBe([
            'password',
            'totp',
            'email_otp',
            'sms_otp',
            'recovery_code',
        ])
        ->and($screen->offeredFactors[0])->toBeInstanceOf(FactorOption::class);
});

it('keeps the filtered factor collection a JSON-list when a host appends a driver', function (): void {
    app(FactorRegistry::class)->register(new class implements Factor
    {
        public function id(): string
        {
            return 'passkey';
        }

        public function kind(): FactorKind
        {
            return FactorKind::Possession;
        }

        public function strength(): FactorStrength
        {
            return FactorStrength::Possession;
        }

        public function maxActiveCredentials(): int
        {
            return 1;
        }

        public function enroll(int $userId, array $data): EnrollmentResult
        {
            return new EnrollmentResult([]);
        }

        public function challenge(\Fissible\Vouch\Factors\ChallengeRequest $request): ?\Fissible\Vouch\Models\AuthChallenge
        {
            return null;
        }

        public function verify(\Fissible\Vouch\Factors\VerificationRequest $request): FactorResult
        {
            return FactorResult::failed(FactorFailure::NoCredential);
        }

        public function revoke(\Fissible\Vouch\Models\AuthCredential $credential): void {}
    });
    app()->forgetInstance(ScreenBuilder::class);

    $options = screenBuilder()->identify(EnumerationPosture::Friendly)->offeredFactors;

    expect(array_keys($options))->toBe(range(0, count($options) - 1))
        ->and(array_map(static fn (FactorOption $option): string => $option->factorId, $options))
        ->toBe(['password', 'totp', 'email_otp', 'sms_otp', 'passkey']);
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

it('keeps retry null when no throttle state was measured', function (): void {
    foreach ([Outcome::IdentifierUnknown, Outcome::CredentialRejected] as $outcome) {
        expect(screenBuilder()->refused(AuthStep::Challenge, $outcome, EnumerationPosture::Strict)->retry)
            ->toBeNull();
    }
});

it('refuses to shape a lock without measured identifier lock state', function (): void {
    screenBuilder()->refused(AuthStep::Challenge, Outcome::Locked, EnumerationPosture::Strict);
})->throws(LogicException::class);

it('carries an ordinary identifier retry through posture shaping', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:30Z');
    $throttle = IdentifierThrottle::backedOff(4, $retryAfter);

    $strict = screenBuilder()->refused(
        AuthStep::Challenge,
        Outcome::CredentialRejected,
        EnumerationPosture::Strict,
        throttle: $throttle,
    );
    $friendly = screenBuilder()->refused(
        AuthStep::Challenge,
        Outcome::CredentialRejected,
        EnumerationPosture::Friendly,
        throttle: $throttle,
    );

    expect($strict->retry?->attemptsRemaining)->toBeNull()
        ->and($strict->retry?->lockedUntil)->toBeNull()
        ->and($strict->retry?->retryAfter)->toBe($retryAfter)
        ->and($friendly->retry?->attemptsRemaining)->toBe(4)
        ->and($friendly->retry?->lockedUntil)->toBeNull()
        ->and($friendly->retry?->retryAfter)->toBe($retryAfter);
});

it('discloses a measured identifier lock but redacts its counter under strict posture', function (): void {
    $lockedUntil = new DateTimeImmutable('2026-08-16T12:15:00Z');
    $screen = screenBuilder()->refused(
        AuthStep::Challenge,
        Outcome::Locked,
        EnumerationPosture::Strict,
        throttle: IdentifierThrottle::locked($lockedUntil),
    );

    expect($screen->errors)->toBe(['Too many attempts. Try again later.'])
        ->and($screen->retry?->attemptsRemaining)->toBeNull()
        ->and($screen->retry?->lockedUntil)->toBe($lockedUntil)
        ->and($screen->retry?->retryAfter)->toBeNull();
});

it('can disclose shared backoff without constructing identifier lock state', function (): void {
    $retryAfter = new DateTimeImmutable('2026-08-16T12:00:05Z');
    $strict = screenBuilder()->refused(
        AuthStep::Challenge,
        Outcome::CredentialRejected,
        EnumerationPosture::Strict,
        throttle: SharedThrottle::backedOff($retryAfter),
    );
    $friendly = screenBuilder()->refused(
        AuthStep::Challenge,
        Outcome::CredentialRejected,
        EnumerationPosture::Friendly,
        throttle: SharedThrottle::backedOff($retryAfter),
    );

    expect($strict->retry?->attemptsRemaining)->toBeNull()
        ->and($strict->retry?->lockedUntil)->toBeNull()
        ->and($strict->retry?->retryAfter)->toBe($retryAfter)
        // Assert the builder's primary mapping independently of strict shaping.
        ->and($friendly->retry?->attemptsRemaining)->toBeNull()
        ->and($friendly->retry?->lockedUntil)->toBeNull()
        ->and($friendly->retry?->retryAfter)->toBe($retryAfter);
});

it('refuses to present shared throttle state as an identifier lock', function (): void {
    screenBuilder()->refused(
        AuthStep::Challenge,
        Outcome::Locked,
        EnumerationPosture::Strict,
        throttle: SharedThrottle::backedOff(new DateTimeImmutable('2026-08-16T12:00:05Z')),
    );
})->throws(LogicException::class);

it('refuses shared state that did not measure an active backoff', function (
    SharedThrottle $throttle,
): void {
    expect(fn () => screenBuilder()->refused(
        AuthStep::Challenge,
        Outcome::CredentialRejected,
        EnumerationPosture::Strict,
        throttle: $throttle,
    ))->toThrow(LogicException::class, 'only when that dimension measured an active backoff');
})->with([
    'observed' => [SharedThrottle::observed()],
    'permitted' => [SharedThrottle::permitted()],
    'skipped' => [SharedThrottle::skipped()],
]);
