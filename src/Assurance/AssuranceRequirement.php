<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

use DateInterval;
use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;

final readonly class AssuranceRequirement
{
    private function __construct(public string $level, private ?DateInterval $maxAge) {}

    public static function from(mixed $value): self
    {
        if (is_string($value)) {
            $level = $value;
            $age = null;
        } elseif (is_array($value) && array_is_list($value) === false && array_keys($value) === array_filter(array_keys($value), static fn ($key): bool => $key === 'level' || $key === 'max_age')) {
            $level = $value['level'] ?? null;
            $raw = $value['max_age'] ?? null;
            if (! is_string($level) || ($raw !== null && ! is_string($raw))) {
                throw new InvalidArgumentException('An assurance requirement is malformed.');
            }
            $age = $raw === null ? null : self::parseInterval($raw);
        } else {
            throw new InvalidArgumentException('An assurance requirement is malformed.');
        }

        if (! AssuranceLevelComparator::isKnown($level)) {
            throw new InvalidArgumentException('Unknown assurance level.');
        }

        return new self($level, $age);
    }

    public function maxAgeSeconds(): ?int
    {
        if ($this->maxAge === null) {
            return null;
        }

        $origin = new DateTimeImmutable('@0');
        $end = $origin->add($this->maxAge);

        return $end->getTimestamp() - $origin->getTimestamp();
    }

    private static function parseInterval(string $value): DateInterval
    {
        // Calendar months and years do not have a stable number of seconds,
        // whereas RFC 9470 requires exactly that quantity on the wire.
        if (! preg_match('/^P(?=\d|T\d)(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?$/', $value)) {
            throw new InvalidArgumentException('max_age must be a non-negative ISO-8601 duration.');
        }

        try {
            return new DateInterval($value);
        } catch (\Exception) {
            throw new InvalidArgumentException('max_age must be a non-negative ISO-8601 duration.');
        }
    }
}
