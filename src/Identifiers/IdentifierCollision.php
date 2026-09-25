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
     * @param  string  $value  the canonical identifier value they contend for
     * @param  list<int>  $ids  every colliding row id, ascending
     */
    public function __construct(
        public string $table,
        public string $value,
        public array $ids,
    ) {}
}
