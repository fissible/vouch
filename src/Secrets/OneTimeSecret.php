<?php

declare(strict_types=1);

namespace Fissible\Vouch\Secrets;

use JsonSerializable;
use SensitiveParameter;

/**
 * Bearer material that may be read once and is redacted everywhere else.
 *
 * A provisioning URI or a recovery code authenticates whoever holds it. As a
 * plain string it reaches a log line, a `dd()`, a queued job payload, or an
 * exception context without anyone deciding it should — that is the default
 * behaviour of every debugging tool in the stack, not a hypothetical.
 *
 * This is containment, not a guarantee. `var_export()` and direct reflection
 * still reach a private property, and no PHP object can prevent that. What it
 * closes are the paths that fire by accident.
 *
 * Deliberately NOT readonly: revealing nulls the value, which is the mechanism.
 */
final class OneTimeSecret implements JsonSerializable
{
    private ?string $value;

    public function __construct(#[SensitiveParameter] string $value)
    {
        $this->value = $value;
    }

    /**
     * @throws SecretAlreadyRevealed on the second and every later call.
     */
    public function reveal(): string
    {
        $value = $this->value ?? throw SecretAlreadyRevealed::make();

        $this->value = null;

        return $value;
    }

    public function __toString(): string
    {
        return '[redacted]';
    }

    /**
     * @return array{value: string}
     */
    public function __debugInfo(): array
    {
        return ['value' => '[redacted]'];
    }

    public function jsonSerialize(): string
    {
        return '[redacted]';
    }

    /**
     * Nulls the value rather than redacting it to a string, so a secret that
     * reached a queue or a cache is unusable on the other side instead of
     * arriving as the literal text "[redacted]" and being treated as a code.
     *
     * @return array{value: null}
     */
    public function __serialize(): array
    {
        return ['value' => null];
    }

    /**
     * @param array{value: null} $data
     */
    public function __unserialize(array $data): void
    {
        $this->value = $data['value'];
    }
}
