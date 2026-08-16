<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

/** Exit values consumed outside Symfony's binary success/failure callbacks. */
enum CommandExit: int
{
    case Success = 0;
    case Failure = 1;
    case DeliveryHealth = 2;
}
