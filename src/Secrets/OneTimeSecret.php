<?php

declare(strict_types=1);

namespace Fissible\Vouch\Secrets;

use JsonSerializable;
use LogicException;
use SensitiveParameter;
use WeakMap;

/**
 * Bearer material that may be read once and is redacted everywhere else.
 *
 * A provisioning URI or a recovery code authenticates whoever holds it. As a
 * plain string it reaches a log line, a `dd()`, a queued job payload, or an
 * exception context without anyone deciding it should — that is the default
 * behaviour of every debugging tool in the stack, not a hypothetical.
 *
 * THE VALUE IS NOT STORED ON THE OBJECT. It lives in a WeakMap keyed by the
 * instance, because `var_export()` reads raw instance properties and consults
 * none of `__debugInfo()`, `__toString()` or `jsonSerialize()`. A redacting
 * property-holder therefore leaks in full through `var_export()` — which is what
 * writes cached config and what several dump helpers and debug toolbars call.
 * With no property to read, that route emits an empty state array.
 *
 * The WeakMap also keeps the lifetime right: the entry is collected with the
 * instance, so a forgotten secret does not linger in a static registry.
 *
 * This is containment, not a guarantee — reflection over this class's static
 * still reaches the map, and nothing in PHP can prevent that. What it closes are
 * the paths that fire by accident, which now includes `var_export()`.
 */
final class OneTimeSecret implements JsonSerializable
{
    /**
     * Values by instance. Static so no instance property can expose it.
     *
     * @var WeakMap<self, string>|null
     */
    private static ?WeakMap $values = null;

    public function __construct(#[SensitiveParameter] string $value)
    {
        self::values()[$this] = $value;
    }

    /**
     * @throws SecretAlreadyRevealed on the second and every later call.
     */
    public function reveal(): string
    {
        $values = self::values();

        if (! isset($values[$this])) {
            throw SecretAlreadyRevealed::make();
        }

        $value = $values[$this];

        // Single use: dropping the entry is the mechanism, exactly as nulling
        // the property was before the value moved off the object.
        unset($values[$this]);

        return $value;
    }

    public function __toString(): string
    {
        return '[redacted]';
    }

    /**
     * Reports that a secret EXISTS without revealing it.
     *
     * An empty array would hide the fact there is anything here, which invites
     * someone to call reveal() to find out — spending the single use to satisfy
     * curiosity.
     *
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
     * Carries no value, so a secret that reached a queue or a cache is unusable
     * on the other side rather than arriving as the literal text "[redacted]"
     * and being treated as a code.
     *
     * @return array{}
     */
    public function __serialize(): array
    {
        return [];
    }

    /**
     * Deliberately registers nothing: the revived instance has no WeakMap entry,
     * so reveal() reports it as already spent.
     *
     * @param array{} $data
     */
    public function __unserialize(array $data): void {}

    /**
     * A clone would be a second object with no entry of its own — silently
     * unusable, and easy to mistake for a copy of the secret. Refusing says so
     * at the point of the mistake.
     */
    public function __clone(): void
    {
        throw new LogicException(
            'A OneTimeSecret cannot be cloned: the value belongs to one instance and is '
            . 'readable once. Pass the original, or reveal() it and handle the string.',
        );
    }

    /**
     * `var_export()` emits a __set_state() call, and evaluating that output must
     * not reconstitute anything usable. It cannot — no state is exported — so
     * this refuses rather than returning a hollow instance that looks like a
     * secret and reveals nothing.
     *
     * @param array<string, mixed> $state
     */
    public static function __set_state(array $state): self
    {
        throw new LogicException(
            'A OneTimeSecret cannot be rebuilt from var_export() output: the value is '
            . 'never exported. This is the redaction working, not a defect.',
        );
    }

    /** @return WeakMap<self, string> */
    private static function values(): WeakMap
    {
        /** @var WeakMap<self, string> */
        return self::$values ??= new WeakMap();
    }
}
