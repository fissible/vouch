<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * Records digest IDENTITY, so provenance can be asserted rather than inferred.
 *
 * Counting verifications proves work happened. It does NOT prove the digest
 * being verified came from the active hasher — and that provenance is the whole
 * point of the mitigation, because a hard-coded bcrypt digest checked by an
 * Argon-configured hasher is rejected instantly, returning FASTER than the real
 * path and inverting the leak it was added to close.
 *
 * make() hands back a unique sentinel; check() records what it was given. If
 * the two match, the digest demonstrably came from this hasher.
 */
final class RecordingHasher implements Hasher
{
    public int $makeCalls = 0;

    /** @var list<string> */
    public array $made = [];

    /** @var list<string> */
    public array $checkedAgainst = [];

    /**
     * @return array<string, mixed>
     */
    public function info($hashedValue): array
    {
        return ['algo' => 'recording', 'algoName' => 'recording', 'options' => []];
    }

    /** @param  array<string, mixed>  $options */
    public function make($value, array $options = []): string
    {
        $this->makeCalls++;

        // Unique per call, so a cached or hard-coded digest cannot masquerade.
        $digest = 'sentinel:' . bin2hex(random_bytes(16));
        $this->made[] = $digest;

        return $digest;
    }

    /** @param  array<string, mixed>  $options */
    public function check($value, $hashedValue, array $options = []): bool
    {
        $this->checkedAgainst[] = (string) $hashedValue;

        return false;
    }

    /** @param  array<string, mixed>  $options */
    public function needsRehash($hashedValue, array $options = []): bool
    {
        return false;
    }
}
