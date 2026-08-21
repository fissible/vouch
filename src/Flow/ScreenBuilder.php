<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Fissible\Vouch\Kernel\Enumeration\ErrorShaper;
use Fissible\Vouch\Kernel\Enumeration\Outcome;
use Fissible\Vouch\Kernel\Screen\AuthStep;
use Fissible\Vouch\Kernel\Screen\FactorOption;
use Fissible\Vouch\Kernel\Screen\FieldSpec;
use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;
use Fissible\Vouch\Throttle\IdentifierThrottle;
use Fissible\Vouch\Throttle\SharedThrottle;
use Fissible\Vouch\Throttle\ThrottleDecision;
use LogicException;

/**
 * Builds the screen a client renders, and is the ONLY component in Phase 2 that
 * may construct a user-visible authentication error.
 *
 * Every error goes through the kernel's ErrorShaper under the tenant's posture.
 * 2.2's drivers report truthfully — NoCredential distinct from Mismatch,
 * BindingMismatch distinct from both — and this is where that truth is filtered
 * for disclosure. Two components deciding disclosure would make the strict
 * posture guarantee unverifiable, which is why there is one.
 *
 * identify() and challenge() take a posture they do not currently read. That is
 * deliberate rather than vestigial: all three methods share one call signature
 * so a caller never has to know which of them shapes errors, and refused() —
 * which does read it — is reached from the same call sites.
 */
final readonly class ScreenBuilder
{
    public function __construct(
        private ErrorShaper $shaper,
        private FactorRegistry $registry,
    ) {}

    public function identify(EnumerationPosture $posture): ScreenSpec
    {
        return new ScreenSpec(
            step: AuthStep::Identify,
            // Fixed, registry-derived choices: the list and its default do not
            // depend on whether the submitted identifier later resolves.
            offeredFactors: $this->offeredFactors('password', includeRecovery: false),
            fields: [new FieldSpec('identifier', 'text', 'username', 255)],
            challengePayload: null,
            errors: [],
            retry: null,
        );
    }

    /**
     * @param  array<string, mixed>|null  $payload
     */
    public function challenge(string $factorId, EnumerationPosture $posture, ?array $payload = null): ScreenSpec
    {
        return new ScreenSpec(
            step: AuthStep::Challenge,
            offeredFactors: $this->offeredFactors($factorId),
            fields: [new FieldSpec('code', 'text', 'one-time-code', 64)],
            challengePayload: $payload,
            errors: [],
            retry: null,
        );
    }

    /**
     * A refusal, shaped for disclosure.
     *
     * @throws LogicException when handed Outcome::Locked.
     */
    public function refused(
        AuthStep $step,
        Outcome $outcome,
        EnumerationPosture $posture,
        ?string $factorId = null,
        IdentifierThrottle|SharedThrottle|null $throttle = null,
        ?bool $captchaRequired = null,
    ): ScreenSpec {
        $measuredLock = $throttle instanceof IdentifierThrottle
            && $throttle->decision === ThrottleDecision::Locked;

        if (($outcome === Outcome::Locked) !== $measuredLock) {
            throw new LogicException(
                'ScreenBuilder requires Outcome::Locked and a measured identifier lock '
                . 'to arrive together. A lock outcome without identifier state fabricates '
                . 'a lockout, while hiding measured lock state would discard the only '
                . 'deadline a legitimate user can act on.',
            );
        }

        if ($throttle instanceof SharedThrottle
            && $throttle->decision !== ThrottleDecision::BackedOff) {
            throw new LogicException(
                'ScreenBuilder can refuse from shared throttle state only when that '
                . 'dimension measured an active backoff.',
            );
        }

        $base = new ScreenSpec(
            step: $step,
            offeredFactors: $factorId === null ? [] : $this->offeredFactors($factorId),
            fields: $step === AuthStep::Identify
                ? [new FieldSpec('identifier', 'text', 'username', 255)]
                : [new FieldSpec('code', 'text', 'one-time-code', 64)],
            challengePayload: null,
            errors: [],
            retry: $this->retryPolicy($throttle),
            captchaRequired: $captchaRequired,
        );

        return $this->shaper->shape($base, $outcome, $posture);
    }

    private function retryPolicy(
        IdentifierThrottle|SharedThrottle|null $throttle,
    ): ?RetryPolicy {
        if ($throttle instanceof IdentifierThrottle) {
            return new RetryPolicy(
                attemptsRemaining: $throttle->attemptsRemaining,
                lockedUntil: $throttle->lockedUntil,
                retryAfter: $throttle->retryAfter,
            );
        }

        if ($throttle instanceof SharedThrottle) {
            return new RetryPolicy(
                attemptsRemaining: null,
                lockedUntil: null,
                retryAfter: $throttle->retryAfter,
            );
        }

        return null;
    }

    /**
     * @return list<FactorOption>
     */
    private function offeredFactors(
        string $defaultFactorId,
        bool $includeRecovery = true,
    ): array
    {
        return array_map(
            fn (Factor $factor): FactorOption => new FactorOption(
                factorId: $factor->id(),
                label: $factor->id(),
                strength: $factor->strength(),
                isDefault: $factor->id() === $defaultFactorId,
            ),
            array_values(array_filter(
                $this->registry->all(),
                static fn (Factor $factor): bool => $includeRecovery
                    || $factor->id() !== 'recovery_code',
            )),
        );
    }
}
