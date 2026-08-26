<?php

declare(strict_types=1);

namespace Fissible\Vouch\Enrollment;

/** Intentionally neutral: accepted does not disclose identifier ownership. */
enum FirstCredentialResult
{
    case Accepted;
}
