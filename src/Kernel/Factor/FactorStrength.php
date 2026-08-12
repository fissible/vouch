<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Factor;

/**
 * Ordered by real-world security, not convenience: passkey > totp > sms > email.
 *
 * Recovery sorts lowest, but ordering is NOT the mechanism that excludes it from
 * satisfying a policy — SatisfiabilityEvaluator filters it explicitly. Relying on
 * ordering alone would let a policy with no minimum strength accept a recovery code
 * as a normal factor.
 */
enum FactorStrength: int
{
    case Recovery = 0;
    case Knowledge = 10;
    case PossessionWeak = 20;
    case Possession = 30;
    case PossessionStrong = 40;

    public function atLeast(self $minimum): bool
    {
        return $this->value >= $minimum->value;
    }
}
