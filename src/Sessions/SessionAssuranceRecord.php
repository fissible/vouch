<?php

declare(strict_types=1);

namespace Fissible\Vouch\Sessions;

use Fissible\Vouch\Assurance\AssuranceEvidence;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Illuminate\Database\ConnectionInterface;

final readonly class SessionAssuranceRecord
{
    public function __construct(private ConnectionInterface $connection, private AssuranceVocabulary $vocabulary) {}

    /** @return array{table:string,checked:int,drifted:int,unreadable:int} */
    public function driftCounts(int $batch): array
    {
        $counts = ['table' => 'auth_sessions', 'checked' => 0, 'drifted' => 0, 'unreadable' => 0];

        foreach ($this->connection->table('auth_sessions')->orderBy('id')->lazyById(max(1, $batch), 'id') as $row) {
            if ($row->assurance_proof === null) {
                continue;
            }

            $counts['checked']++;
            $evidence = AssuranceEvidence::fromProof($row->assurance_proof);
            if ($evidence === null || $row->acr === null) {
                $counts['unreadable']++;

                continue;
            }
            if ($row->acr !== $this->vocabulary->name($evidence->facts())) {
                $counts['drifted']++;
            }
        }

        return $counts;
    }
}
