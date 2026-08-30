<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Assurance\AssuranceReason;

final readonly class SessionEvidenceRead
{
    public function __construct(public ?AssuranceEvidence $evidence, public AssuranceReason $reason) {}
}
