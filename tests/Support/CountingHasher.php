<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Illuminate\Contracts\Hashing\Hasher;

/**
 * Counts verification work without changing what it returns.
 *
 * Timing equalization is tested by WORK PERFORMED, not wall-clock duration. A
 * duration assertion would be flaky in CI and would pass or fail for reasons
 * unrelated to the control -- which is a vacuous test wearing a security
 * costume. Counting check() calls is deterministic and measures the thing.
 */
final class CountingHasher implements Hasher
{
    public int $checks = 0;

    public function __construct(private readonly Hasher $inner) {}

    /**
     * @return array<string, mixed>
     */
    public function info($hashedValue): array
    {
        return $this->inner->info($hashedValue);
    }

    /** @param  array<string, mixed>  $options */
    public function make($value, array $options = []): string
    {
        return $this->inner->make($value, $options);
    }

    /** @param  array<string, mixed>  $options */
    public function needsRehash($hashedValue, array $options = []): bool
    {
        return $this->inner->needsRehash($hashedValue, $options);
    }

    /** @param  array<string, mixed>  $options */
    public function check($value, $hashedValue, array $options = []): bool
    {
        $this->checks++;

        return $this->inner->check($value, $hashedValue, $options);
    }
}
