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
            return $this->withErrors($spec, ['Too many attempts. Try again later.'], $spec->retry);
        }

        if ($posture === EnumerationPosture::Strict) {
            // One message, one shape, regardless of what actually happened.
            // Retry state is withheld because a differing attempt counter is
            // itself an oracle for whether the account exists.
            return $this->withErrors($spec, [self::UNIFORM], null);
        }

        $errors = match ($outcome) {
            Outcome::IdentifierUnknown => ['No account matches that identifier.'],
            Outcome::CredentialRejected => ['That credential was not accepted.'],
            Outcome::IdentifierKnown => [],
        };

        return $this->withErrors($spec, $errors, $spec->retry);
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
        );
    }
}
