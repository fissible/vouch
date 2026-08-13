<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Enumeration\EnumerationPosture;
use Illuminate\Contracts\Hashing\Hasher;

/**
 * Equalizes the credential-verification branch under strict posture.
 *
 * A uniform HTTP status closes the status channel; it does not close the timing
 * one. An unknown identifier that skips the verify returns measurably faster
 * than a known one that performs it, and that difference reconstructs the
 * account-existence oracle strict posture exists to deny. Careful body
 * filtering and a uniform status are both defeated by a stopwatch.
 *
 * BOUNDARY, stated honestly: this equalizes the credential-verification branch.
 * It does not promise end-to-end constant time, and full constant-time
 * guarantees across the whole flow are neither achievable nor worth pretending
 * to.
 */
final class VerificationEqualizer
{
    private ?string $dummy = null;

    public function __construct(private readonly Hasher $hasher) {}

    public function equalize(EnumerationPosture $posture): void
    {
        if ($posture !== EnumerationPosture::Strict) {
            return;
        }

        /*
         * The digest comes from the ACTIVE hasher, never a hard-coded bcrypt
         * string. An Argon-configured hasher rejects a bcrypt digest
         * immediately, which would make this branch return FASTER than the real
         * one and invert the very leak it closes.
         */
        $this->dummy ??= $this->hasher->make('vouch-timing-equalization-placeholder');

        $this->hasher->check('vouch-timing-equalization-placeholder', $this->dummy);
    }
}
