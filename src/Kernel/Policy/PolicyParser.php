<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

use Fissible\Vouch\Kernel\Factor\FactorStrength;
use InvalidArgumentException;

final class PolicyParser
{
    /**
     * @param array<string, mixed> $config
     */
    public function parse(array $config): Requirement
    {
        $hasAll = array_key_exists('all_of', $config);
        $hasAny = array_key_exists('any_of', $config);

        if ($hasAll === $hasAny) {
            throw new InvalidArgumentException(
                'A policy node must declare exactly one of all_of or any_of.',
            );
        }

        $key = $hasAll ? 'all_of' : 'any_of';
        $children = $config[$key];

        if (! is_array($children) || $children === []) {
            throw new InvalidArgumentException(
                sprintf('A policy node\'s %s must not be empty.', $key),
            );
        }

        $parsed = array_map($this->parseChild(...), array_values($children));

        if ($hasAny) {
            return new AnyOf($parsed);
        }

        return new AllOf(
            requirements: $parsed,
            requireDistinctCredentials: (bool) ($config['require_distinct_credentials'] ?? true),
            requireIndependentAuthenticators: (bool) ($config['require_independent_authenticators'] ?? false),
        );
    }

    private function parseChild(mixed $child): Requirement
    {
        if (is_string($child)) {
            return new FactorRequirement($child);
        }

        if (! is_array($child)) {
            throw new InvalidArgumentException(
                'A policy child must be a factor name or an array.',
            );
        }

        if (array_key_exists('all_of', $child) || array_key_exists('any_of', $child)) {
            return $this->parse($child);
        }

        if (! array_key_exists('factor', $child) || ! is_string($child['factor'])) {
            throw new InvalidArgumentException(
                'A leaf policy node must declare a string factor.',
            );
        }

        return new FactorRequirement(
            factorId: $child['factor'],
            userVerified: isset($child['user_verified']) ? (bool) $child['user_verified'] : null,
            minimumStrength: $this->parseStrength($child['minimum_strength'] ?? null),
            phishingResistant: isset($child['phishing_resistant']) ? (bool) $child['phishing_resistant'] : null,
        );
    }

    private function parseStrength(mixed $name): ?FactorStrength
    {
        if ($name === null) {
            return null;
        }

        $strength = match ($name) {
            'recovery' => FactorStrength::Recovery,
            'knowledge' => FactorStrength::Knowledge,
            'possession_weak' => FactorStrength::PossessionWeak,
            'possession' => FactorStrength::Possession,
            'possession_strong' => FactorStrength::PossessionStrong,
            default => null,
        };

        if ($strength === null) {
            throw new InvalidArgumentException(
                sprintf('unknown minimum_strength: %s', var_export($name, true)),
            );
        }

        return $strength;
    }
}
