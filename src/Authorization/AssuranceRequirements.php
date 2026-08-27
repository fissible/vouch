<?php

declare(strict_types=1);

namespace Fissible\Vouch\Authorization;

use Fissible\Vouch\Http\AssuranceComparator;
use InvalidArgumentException;
use RuntimeException;

/** Validated ability names prevent configured requirements becoming unreachable. */
final readonly class AssuranceRequirements
{
    /** @var array<string, string> */
    private array $requirements;

    /** @param array<string, string> $requirements */
    private function __construct(array $requirements)
    {
        $this->requirements = $requirements;
    }

    public static function from(mixed $value): self
    {
        if (! is_array($value)) {
            throw new InvalidArgumentException('Configuration "vouch.assurance_requirements" must be an array; got ' . self::describe($value) . '.');
        }

        $requirements = [];
        foreach ($value as $ability => $level) {
            if (! is_string($ability) || ! self::canonical($ability)) {
                throw new InvalidArgumentException('Configuration "vouch.assurance_requirements" has an invalid ability name ' . self::describe($ability) . '.');
            }
            if (! is_string($level) || ! AssuranceComparator::isKnown($level)) {
                throw new InvalidArgumentException('Configuration "vouch.assurance_requirements" has invalid level ' . self::describe($level) . ' for "' . $ability . '".');
            }
            $requirements[$ability] = $level;
        }

        return new self($requirements);
    }

    /** @return list<string> */
    public static function declaredFrom(mixed $value): array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            throw new InvalidArgumentException('Configuration "vouch.declared_abilities" must be a list of canonical strings; got ' . self::describe($value) . '.');
        }
        foreach ($value as $ability) {
            if (! is_string($ability) || ! self::canonical($ability)) {
                throw new InvalidArgumentException('Configuration "vouch.declared_abilities" has an invalid ability name ' . self::describe($ability) . '.');
            }
        }

        /** @var list<string> $value */
        return $value;
    }

    public function levelFor(string $ability): ?string
    {
        return $this->requirements[$ability] ?? null;
    }

    /** @param list<string> $abilities */
    public function strongestFor(array $abilities): ?string
    {
        $strongest = null;
        foreach ($abilities as $ability) {
            $level = $this->levelFor($ability);
            if (
                $level !== null
                && ($strongest === null || AssuranceComparator::strength($level) > AssuranceComparator::strength($strongest))
            ) {
                $strongest = $level;
            }
        }
        return $strongest;
    }

    /** @return array<string, string> */
    public function all(): array
    {
        return $this->requirements;
    }

    /** @param list<string> $declared */
    public function assertDeclared(array $declared): void
    {
        $missing = array_keys(array_filter($this->requirements, static fn (string $_, string $ability): bool => ! in_array($ability, $declared, true), ARRAY_FILTER_USE_BOTH));
        if ($missing !== []) {
            throw new RuntimeException('Configuration "vouch.declared_abilities" does not declare mapped abilities: ' . implode(', ', $missing) . '.');
        }
    }

    private static function canonical(string $ability): bool
    {
        // A configured key is looked up byte-for-byte from middleware and
        // Gate. Reject whitespace that PHP arrays would retain but readers
        // would overlook, rather than making a mapped policy unreachable.
        return $ability !== '' && trim($ability) === $ability;
    }

    private static function describe(mixed $value): string
    {
        return is_string($value) ? '"' . $value . '"' : var_export($value, true);
    }
}
