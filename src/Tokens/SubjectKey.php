<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use InvalidArgumentException;
use Illuminate\Database\Eloquent\Model;

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

    /**
     * Derive the provider from the host's configured user model.
     *
     * Token and session evidence persist the model's morph class, rather than
     * its PHP class name. Credential writers must use that same identity or a
     * successful-looking mutation can fail to find the subject's assurances.
     */
    public static function forConfiguredUser(mixed $id): self
    {
        $model = config('auth.providers.users.model');

        if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
            throw new \RuntimeException('auth.providers.users.model is not an Eloquent model.');
        }

        return self::of((new $model)->getMorphClass(), $id);
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

    public function render(): string
    {
        return $this->toString();
    }

    public function equals(self $other): bool
    {
        return $this->provider === $other->provider && $this->id === $other->id;
    }
}
