<?php

declare(strict_types=1);

namespace Fissible\Vouch\Identifiers;

/**
 * One set of rows that a deterministic identifier equality cannot keep apart.
 *
 * Structured rather than a sentence, because the operator has to act on it: the
 * rows named here are the ones that must be reconciled before the upgrade can
 * proceed, and a prose message forces them to parse row ids back out of it.
 */
final readonly class IdentifierCollision
{
    /**
     * @param  string  $table  the table holding the colliding rows
     * @param  string  $value  the canonical value they contend for; a split
     *                         lands on more than one, and this is the
     *                         lowest-numbered row's
     * @param  list<int>  $ids  every colliding row id, ascending
     * @param  list<string>  $canonicalValues  every canonical value the group
     *                                         lands on, ascending: one for a
     *                                         merge, several for a split
     */
    public function __construct(
        public string $table,
        public string $value,
        public array $ids,
        public array $canonicalValues,
    ) {}
}
