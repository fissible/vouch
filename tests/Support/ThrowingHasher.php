<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Illuminate\Contracts\Hashing\Hasher;
use RuntimeException;

/**
 * A hasher that fails when a code is hashed for storage.
 *
 * Issuing a proof hashes the new code inside the same transaction that must
 * supersede the previous one, so failing here is a realistic way to interrupt
 * an issuance midway: the supersession may already have run, and the new proof
 * certainly has not been written.
 *
 * check() still works, because a test that provokes a failed issuance then has
 * to redeem the PREVIOUS code to prove it survived.
 */
final class ThrowingHasher implements Hasher
{
    public int $makeCalls = 0;

    public function __construct(private readonly Hasher $inner) {}

    /** @param array<string, mixed> $options */
    public function make($value, array $options = []): string
    {
        $this->makeCalls++;

        throw new RuntimeException('The hasher failed while issuing a proof.');
    }

    /** @param array<string, mixed> $options */
    public function check($value, $hashedValue, array $options = []): bool
    {
        return $this->inner->check((string) $value, (string) $hashedValue, $options);
    }

    /** @param array<string, mixed> $options */
    public function needsRehash($hashedValue, array $options = []): bool
    {
        return $this->inner->needsRehash((string) $hashedValue, $options);
    }

    /** @return array{algo: string|int|null, algoName: string, options: array<string, mixed>} */
    public function info($hashedValue): array
    {
        /** @var array{algo: string|int|null, algoName: string, options: array<string, mixed>} $info */
        $info = $this->inner->info((string) $hashedValue);

        return $info;
    }
}
