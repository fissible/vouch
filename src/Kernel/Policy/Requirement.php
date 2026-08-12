<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Policy;

/**
 * Marker. The tree is pure data; SatisfiabilityEvaluator holds the algorithm, so
 * that the one piece of logic worth mutation-testing lives in one place.
 */
interface Requirement {}
