<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/**
 * Policy is satisfied. The session has NOT been rotated yet — that is
 * SessionLifecycle's job, and it happens before anything is serialized.
 */
final readonly class Authenticated implements FlowResult
{
    public function __construct(
        public AuthSuccess $success,
        public ScreenSpec $screen,
    ) {}
}
