<?php

declare(strict_types=1);

namespace Fissible\Vouch\Verification;

enum IdentifierVerificationOutcome
{
    case Verified;
    case Refused;
}
