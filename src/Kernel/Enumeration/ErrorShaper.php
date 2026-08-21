<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Enumeration;

use Fissible\Vouch\Kernel\Screen\RetryPolicy;
use Fissible\Vouch\Kernel\Screen\ScreenSpec;

final class ErrorShaper
{
    private const UNIFORM = 'Check your email to continue.';

    public function shape(
        ScreenSpec $spec,
        Outcome $outcome,
        EnumerationPosture $posture,
    ): ScreenSpec {
        if ($outcome === Outcome::Locked) {
            // Locked is disclosed under every posture: the distinct message and
            // measured deadline survive. Withholding them is useless (the lockout
            // is observable from the failure to proceed) and hostile (a real user
            // cannot tell why they are stuck). The counter remains posture-sensitive.
            //
            // PRECONDITION — this carve-out is safe ONLY under spec §7.1: rate
            // limits must be applied identically to known and unknown
            // identifiers, including the length of the lockout window. Under that
            // condition an unknown identifier reaches Locked on the same schedule
            // and the two responses stay indistinguishable.
            //
            // The kernel is handed the Outcome; it cannot verify this. If Phase 2
            // throttles per existing-account record — the obvious implementation,
            // since the record is where a counter naturally lives — unknown
            // identifiers never lock. The attacker then submits N+1 attempts per
            // candidate: a known identifier returns "Too many attempts. Try again
            // later." with a populated RetryPolicy, an unknown one returns the
            // uniform message with retry: null. That is a complete, cheap
            // account-existence oracle obtained *under Strict posture*, with every
            // kernel test green. Differing lockout windows (15 min real vs 1 min
            // decoy) are the same oracle at finer grain.
            //
            // Recorded as a Phase 2 constraint in the §7.7 residual-risk table.
            $retry = $posture === EnumerationPosture::Strict
                ? $this->strictLockRetry($spec->retry)
                : $spec->retry;

            return $this->withErrors($spec, ['Too many attempts. Try again later.'], $retry);
        }

        if ($posture === EnumerationPosture::Strict) {
            // One message, one shape, regardless of what actually happened.
            // Counter and lock state are withheld because either can become an
            // account-existence oracle. A measured ordinary retry deadline may
            // survive only under the precondition documented on RetryPolicy:
            // known and nonexistent identifiers advance identically. A policy
            // with no measured deadline remains null rather than fabricating an
            // empty retry object.
            return $this->withErrors($spec, [self::UNIFORM], $this->strictRetry($spec->retry));
        }

        // Deliberately non-exhaustive: Outcome::Locked is omitted because the
        // early return above already handles it. If that guard is ever
        // removed, this match must fail loudly (UnhandledMatchError) rather
        // than silently falling through — do not add a default arm.
        $errors = match ($outcome) {
            Outcome::IdentifierUnknown => ['No account matches that identifier.'],
            Outcome::CredentialRejected => ['That credential was not accepted.'],
            Outcome::IdentifierKnown => [],
        };

        return $this->withErrors($spec, $errors, $spec->retry);
    }

    private function strictRetry(?RetryPolicy $retry): ?RetryPolicy
    {
        if ($retry?->retryAfter === null) {
            return null;
        }

        return new RetryPolicy(
            attemptsRemaining: null,
            lockedUntil: null,
            retryAfter: $retry->retryAfter,
        );
    }

    private function strictLockRetry(?RetryPolicy $retry): ?RetryPolicy
    {
        if ($retry === null) {
            return null;
        }

        return new RetryPolicy(
            attemptsRemaining: null,
            lockedUntil: $retry->lockedUntil,
            retryAfter: $retry->retryAfter,
        );
    }

    /**
     * @param list<string> $errors
     */
    private function withErrors(
        ScreenSpec $spec,
        array $errors,
        ?RetryPolicy $retry,
    ): ScreenSpec {
        return new ScreenSpec(
            step: $spec->step,
            offeredFactors: $spec->offeredFactors,
            fields: $spec->fields,
            challengePayload: $spec->challengePayload,
            errors: $errors,
            retry: $retry,
            captchaRequired: $spec->captchaRequired,
        );
    }
}
