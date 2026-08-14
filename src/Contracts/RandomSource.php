<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

/**
 * A source of uniform random integers, injectable so generator BOUNDS are
 * testable.
 *
 * This exists for one reason. Recovery codes and OTP codes are drawn one
 * character at a time with a call of the form `int(0, $max)`, and both ends of
 * that range are load-bearing: an off-by-one at the bottom silently removes a
 * character from every code the system will ever issue. That is an entropy
 * defect in authentication-secret generation, and with `random_int()` called
 * inline it is only observable statistically — which means either a flaky test
 * or no test.
 *
 * With the source injected, a test double that returns its own lower bound makes
 * the boundary deterministic: the generator must produce the FIRST character of
 * its alphabet, every time.
 */
interface RandomSource
{
    /**
     * A uniform random integer in [$min, $max], inclusive at both ends.
     *
     * @return int Cryptographically secure in production.
     */
    public function int(int $min, int $max): int;
}
