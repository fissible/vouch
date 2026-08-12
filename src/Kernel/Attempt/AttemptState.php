<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Attempt;

enum AttemptState: string
{
    case Initiated = 'initiated';
    case Identified = 'identified';
    case FactorPending = 'factor_pending';
    case FactorSatisfied = 'factor_satisfied';
    case Authenticated = 'authenticated';
    case RegistrationRequired = 'registration_required';
    case Failed = 'failed';
    case Locked = 'locked';
}
