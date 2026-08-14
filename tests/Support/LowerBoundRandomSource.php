<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Contracts\RandomSource;

/**
 * Always returns the lower bound it was asked for.
 *
 * This makes a generator's BOUNDARY deterministic rather than statistical. A
 * generator drawing from `int(0, $max)` must produce the first character of its
 * alphabet on every draw; if the lower bound is off by one, it produces a
 * different character on every draw. Either way the answer is the same on every
 * run, which is what a distribution test cannot give.
 *
 * It records what it was asked for, so a test can assert the RANGE as well as
 * the result -- a generator that quietly asked for `int(1, $max)` would still
 * be self-consistent otherwise.
 *
 * Not a substitute for the aggregate coverage tests, which exercise the real
 * CSPRNG across the whole alphabet. This pins the ends; those pin the middle.
 */
final class LowerBoundRandomSource implements RandomSource
{
    /** @var list<array{min: int, max: int}> */
    public array $calls = [];

    public function int(int $min, int $max): int
    {
        $this->calls[] = ['min' => $min, 'max' => $max];

        return $min;
    }
}
