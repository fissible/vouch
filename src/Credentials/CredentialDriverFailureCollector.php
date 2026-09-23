<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

use Illuminate\Database\Connection;

/** Carries failures through void factor calls without changing their contract. */
final class CredentialDriverFailureCollector
{
    /** @var list<array{connection: Connection, report: CredentialDriverFailureReport, operation: ?CredentialDriverFailureReport}> */
    private array $active = [];

    public function collect(Connection $connection, callable $write): CredentialDriverFailureReport
    {
        $report = new CredentialDriverFailureReport;
        $this->active[] = ['connection' => $connection, 'report' => $report, 'operation' => null];

        try {
            $write();
        } finally {
            array_pop($this->active);
        }

        return $report;
    }

    /**
     * Bind each pending collection to the first mutation entered on its
     * connection. Its report is also its operation identity: a nested mutation
     * has a different report, even when it writes the same subject.
     *
     * Matching on the connection alone was wrong: an observer running its own
     * mutation during the collected call had its failures attributed to the
     * caller, which then named a token it never touched. Matching on the
     * subject as well does not fix it, because both operations can belong to
     * one user.
     *
     * The cost of first-wins is that a second, SEQUENTIAL mutation in the same
     * collected call is excluded too. No shipped factor performs two; see the
     * note on Factor::revoke().
     *
     * @return list<CredentialDriverFailureReport>
     */
    public function reportsFor(Connection $connection, CredentialDriverFailureReport $operation): array
    {
        $reports = [];
        foreach ($this->active as $index => $scope) {
            if ($scope['connection'] !== $connection) {
                continue;
            }

            if ($scope['operation'] === null) {
                $this->active[$index]['operation'] = $operation;
            } elseif ($scope['operation'] !== $operation) {
                continue;
            }

            $reports[] = $scope['report'];
        }

        return $reports;
    }
}
