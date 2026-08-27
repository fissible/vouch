<?php

declare(strict_types=1);

namespace Fissible\Vouch\SelfService;

/** The deliberately small, non-enumerating result vocabulary for credential changes. */
enum SelfServiceOutcome: string
{
    case Completed = 'completed';
    case RecoveryRestricted = 'recovery_restricted';
    case StepUpRequired = 'step_up_required';
    case RequiredByPolicy = 'required_by_policy';
    case Refused = 'refused';
}
