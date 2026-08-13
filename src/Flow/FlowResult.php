<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

/**
 * The outcome of advancing an attempt.
 *
 * A typed result rather than a bare ScreenSpec. Returning only a screen would
 * force the controller to infer completion from screen contents — exactly the
 * branching on AuthStep that the HTTP boundary forbids — and would leave
 * session rotation with no explicit seam to hang from.
 */
interface FlowResult {}
