<?php

declare(strict_types=1);

namespace Fissible\Vouch\Assurance;

final readonly class EvidenceRead
{
    public function __construct(public ?AssuranceEvidence $evidence, public AssuranceReason $reason) {}
}
