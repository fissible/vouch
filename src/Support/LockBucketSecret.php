<?php

declare(strict_types=1);

namespace Fissible\Vouch\Support;

use Illuminate\Support\Facades\Config;
use RuntimeException;

/**
 * #16. The one secret every bucketed mutex is keyed on, plus the previous one
 * during a rotation overlap.
 *
 * Dedicated rather than APP_KEY: rotating APP_KEY must stay survivable, and if
 * it also remapped every mutex, old and new processes would stop serializing
 * mid-rollout. Rotating THIS secret has that cost, which the previous secret
 * removes. While it is set, every lock takes the bucket under both secrets, so a
 * process still on the old configuration and an updated one always share one.
 *
 * `vouch.issuance_locks.secret` is #46's name for the same value. It is read only
 * when the shared key is unset, so an existing install keeps its mapping without
 * changing anything.
 */
final class LockBucketSecret
{
    public const KEY = 'vouch.lock_buckets.secret';

    public const PREVIOUS_KEY = 'vouch.lock_buckets.previous_secret';

    public const LEGACY_KEY = 'vouch.issuance_locks.secret';

    /**
     * hash_hmac accepts a one-character key, so without a floor a placeholder
     * boots, works, looks set, and is brute-forceable offline.
     */
    private const MINIMUM_BYTES = 32;

    public static function current(): string
    {
        $configured = self::read(self::KEY);
        $name = self::KEY . ' (VOUCH_LOCK_BUCKETS_SECRET)';

        if ($configured === null) {
            $configured = self::read(self::LEGACY_KEY);
            $name = self::LEGACY_KEY . ' (VOUCH_ISSUANCE_LOCKS_SECRET)';
        }

        if ($configured === null) {
            throw new RuntimeException(
                'Vouch requires a dedicated lock-bucket secret: set ' . self::KEY
                . ' (VOUCH_LOCK_BUCKETS_SECRET). The package ships no default, because '
                . 'a shared one would give every installation the same derivable bucket mapping.',
            );
        }

        // Named by the key actually read, so a short legacy value is reported
        // where the operator set it.
        return self::long($configured, $name);
    }

    public static function previous(): ?string
    {
        $configured = self::read(self::PREVIOUS_KEY);

        return $configured === null
            ? null
            : self::long($configured, self::PREVIOUS_KEY . ' (VOUCH_LOCK_BUCKETS_PREVIOUS_SECRET)');
    }

    /** @return non-empty-list<string> current first */
    public static function all(): array
    {
        $previous = self::previous();

        return $previous === null ? [self::current()] : [self::current(), $previous];
    }

    /** Whether a rotation overlap is configured, valid or not. */
    public static function overlapConfigured(): bool
    {
        return self::read(self::PREVIOUS_KEY) !== null;
    }

    /** Boot and vouch:doctor call this, so both refuse on the same conditions. */
    public static function assertConfigured(): void
    {
        self::all();
    }

    private static function read(string $key): ?string
    {
        $value = Config::get($key);

        return is_string($value) && $value !== '' ? $value : null;
    }

    private static function long(string $secret, string $name): string
    {
        if (strlen($secret) < self::MINIMUM_BYTES) {
            throw new RuntimeException(sprintf(
                'The lock-bucket secret is too short: %s needs at least %d bytes.',
                $name,
                self::MINIMUM_BYTES,
            ));
        }

        return $secret;
    }
}
