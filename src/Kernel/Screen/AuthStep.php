<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Screen;

enum AuthStep: string
{
    case Identify = 'identify';
    case Challenge = 'challenge';
    case Enroll = 'enroll';
    case Recover = 'recover';
    case StepUp = 'step_up';
}
