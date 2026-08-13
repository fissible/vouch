<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use Fissible\Vouch\Kernel\Screen\ScreenSpec;

/**
 * The attempt advanced and wants another interaction.
 *
 * Carries the handle because a client has nothing to advance with otherwise —
 * beginning an attempt is precisely the case where the client does not yet have
 * one. Null on a refusal for an unknown or mismatched handle: echoing one back
 * would let a caller learn which handles exist.
 */
final readonly class Continuing implements FlowResult
{
    public function __construct(
        public ScreenSpec $screen,
        public ?string $handle = null,
    ) {}
}
