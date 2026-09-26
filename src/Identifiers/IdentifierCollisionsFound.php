<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

use RuntimeException;

/**
 * The identifier upgrade refused: rows disagree with the new definition of
 * identity in a way only a human can settle.
 *
 * Every colliding group across every table travels on the exception, not just
 * the first one found. An operator who fixes what a partial report named and
 * re-runs would simply be refused again over something the first pass already
 * knew about.
 */
final class IdentifierCollisionsFound extends RuntimeException
{
    /**
     * @param  list<IdentifierCollision>  $groups
     */
    public function __construct(public readonly array $groups)
    {
        parent::__construct(self::describe($groups));
    }

    /**
     * @param  list<IdentifierCollision>  $groups
     */
    private static function describe(array $groups): string
    {
        $lines = [];

        foreach ($groups as $group) {
            /*
             * A split reads the opposite way round from a merge, so it says so.
             * "rows 4, 7 all claim jose@" would tell an operator that two rows
             * want one address, when what happened is that this database
             * considers them one address and the change makes them two -- and
             * naming one of the two canonical values hides which.
             */
            $lines[] = count($group->canonicalValues) > 1
                ? sprintf(
                    '  %s: rows %s are one identifier to this database, and canonicalize apart onto %s',
                    $group->table,
                    implode(', ', $group->ids),
                    implode(' and ', $group->canonicalValues),
                )
                : sprintf(
                    '  %s: rows %s all claim %s',
                    $group->table,
                    implode(', ', $group->ids),
                    $group->value,
                );
        }

        return "Identifier rows collide under deterministic equality; nothing was changed.\n"
            . implode("\n", $lines)
            . "\nReconcile these rows, then run the migration again.";
    }
}
