<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use InvalidArgumentException;

/**
 * Canonical, provider-qualified identity for a token subject.
 *
 * IDs remain strings after construction. Numeric coercion would make `07` and
 * `7` answer for the same subject, which can attach one subject's assurance to
 * another. Colons are forbidden only in IDs: that leaves the final colon as
 * the unambiguous persistence separator while allowing namespaced providers.
 */
final readonly class SubjectKey
{
    private function __construct(
        public string $provider,
        public string $id,
    ) {}

    public static function of(mixed $provider, mixed $id): self
    {
        if (! is_string($provider) || $provider === '') {
            throw new InvalidArgumentException('A subject provider must be a non-empty string.');
        }

        if ((! is_string($id) && ! is_int($id)) || (string) $id === '' || str_contains((string) $id, ':')) {
            throw new InvalidArgumentException('A subject id must be a non-empty string or integer without a colon.');
        }

        return new self($provider, (string) $id);
    }

    public static function fromString(string $value): self
    {
        $separator = strrpos($value, ':');

        if ($separator === false) {
            throw new InvalidArgumentException('A subject key must contain a provider and id separator.');
        }

        return self::of(substr($value, 0, $separator), substr($value, $separator + 1));
    }

    public function toString(): string
    {
        return $this->provider . ':' . $this->id;
    }

    public function equals(self $other): bool
    {
        return $this->provider === $other->provider && $this->id === $other->id;
    }
}
