<?php

declare(strict_types=1);

namespace Fissible\Vouch\Flow;

use LogicException;

/**
 * A FlowResult variant nothing knows how to handle.
 *
 * PHP has no sealed interfaces, so a future variant can be added without every
 * handler learning about it. Falling through to "serialize whatever screen we
 * have" would silently skip session rotation on a successful authentication —
 * the user would appear logged in and hold no record. Throwing is the same
 * discipline DatabaseAttemptStore applies to UnknownMutation.
 */
final class UnknownFlowResult extends LogicException
{
    public static function for(FlowResult $result): self
    {
        return new self(sprintf(
            'No handler for FlowResult variant %s. Every variant must be handled '
            . 'explicitly; falling through would skip session rotation on success.',
            $result::class,
        ));
    }
}
