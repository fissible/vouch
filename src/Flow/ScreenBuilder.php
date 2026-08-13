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
use Fissible\Vouch\Kernel\Screen\ScreenSpec;
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
            offeredFactors: [],
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
    ): ScreenSpec {
        if ($outcome === Outcome::Locked) {
            throw new LogicException(
                'ScreenBuilder cannot shape Outcome::Locked in Phase 2.3. ErrorShaper '
                . 'discloses Locked in full under every posture, which is safe only when '
                . 'rate limits apply identically to known and unknown identifiers — and '
                . '2.3 ships no rate limiting, so nothing can honestly be locked. Emitting '
                . 'it with a null RetryPolicy would fabricate a lockout nobody measured. '
                . 'Phase 2.3b removes this guard once it can satisfy the precondition.',
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
            retry: null,
        );

        return $this->shaper->shape($base, $outcome, $posture);
    }

    /**
     * @return list<FactorOption>
     */
    private function offeredFactors(string $defaultFactorId): array
    {
        return array_map(
            fn (Factor $factor): FactorOption => new FactorOption(
                factorId: $factor->id(),
                label: $factor->id(),
                strength: $factor->strength(),
                isDefault: $factor->id() === $defaultFactorId,
            ),
            $this->registry->all(),
        );
    }
}
