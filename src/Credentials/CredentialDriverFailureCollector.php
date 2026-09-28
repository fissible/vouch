<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

use Illuminate\Database\Connection;

/** Carries failures through void factor calls without changing their contract. */
final class CredentialDriverFailureCollector
{
    /** @var list<array{connection: Connection, depth: int, report: CredentialDriverFailureReport}> */
    private array $active = [];

    /**
     * The connection of every mutation currently in flight, innermost last. A
     * connection appears once per enclosing mutation, so counting its entries
     * is that connection's mutation nesting depth.
     *
     * Held as the connections themselves rather than a per-connection tally:
     * a Connection is not a valid array key, and keying on spl_object_id()
     * would rely on an object nobody here holds a reference to still being
     * alive.
     *
     * @var list<Connection>
     */
    private array $inFlight = [];

    public function collect(Connection $connection, callable $write): CredentialDriverFailureReport
    {
        $report = new CredentialDriverFailureReport;

        // Bound here, not at the first mutation that asks. First-ask binding
        // makes the collection describe whichever mutation happened to arrive
        // first, so a foreign one arriving before the caller's own would claim
        // the channel and exclude the work the caller actually asked for.
        $this->active[] = [
            'connection' => $connection,
            'depth' => $this->depth($connection),
            'report' => $report,
        ];

        try {
            $write();
        } finally {
            array_pop($this->active);
        }

        return $report;
    }

    /**
     * Run a mutation's body with that mutation marked in flight.
     *
     * CredentialMutation wraps itself in this AFTER asking for its reports: a
     * mutation must not be counted among the mutations enclosing it.
     *
     * @template TMutation
     *
     * @param  callable(): TMutation  $mutate
     * @return TMutation
     */
    public function during(Connection $connection, callable $mutate): mixed
    {
        $this->inFlight[] = $connection;

        try {
            return $mutate();
        } finally {
            array_pop($this->inFlight);
        }
    }

    /**
     * The channels a mutation entered now must report into.
     *
     * A collection takes the mutations that begin at the nesting depth the
     * collected call itself began at. That is what separates the two shapes the
     * collector otherwise sees as one, both being "another mutation on this
     * connection during the collected call": a factor's own second mutation
     * begins after its first FINISHED, so at the collected call's own depth,
     * while a mutation an observer starts begins from INSIDE one that is still
     * running, so a level deeper. A factor may therefore perform as many
     * mutations as it likes and every one of them reports.
     *
     * Three cheaper discriminators were tried and are wrong. The connection
     * alone attributed an observer's own mutation to the caller, which then
     * named a token it never touched. Adding the subject does not help, because
     * both operations can belong to one user. Transaction level does not help
     * either: mutateCredentials() wraps the factor call in a transaction, so
     * the factor's own mutations and a nested observer's all sit at level 1.
     *
     * @return list<CredentialDriverFailureReport>
     */
    public function reportsFor(Connection $connection): array
    {
        $depth = $this->depth($connection);
        $reports = [];

        foreach ($this->active as $scope) {
            if ($scope['connection'] === $connection && $scope['depth'] === $depth) {
                $reports[] = $scope['report'];
            }
        }

        return $reports;
    }

    /** How many mutations on $connection are in flight. */
    private function depth(Connection $connection): int
    {
        $depth = 0;
        foreach ($this->inFlight as $inFlight) {
            if ($inFlight === $connection) {
                $depth++;
            }
        }

        return $depth;
    }
}
