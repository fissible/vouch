<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

enum CredentialRecoveryOutcome
{
    case GraceOpened;
    case Reset;
    case CredentialChangeFailed;
    case Refused;
    case SecondFactorRequired;
}
