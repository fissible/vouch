<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

/**
 * Record counts and issuer error details from reclaiming orphaned assurance records.
 *
 * `reclaimed`, `retained`, `unsupported`, and `errored` are all assurance-record
 * counts; an errored record was held because its issuer could not be queried.
 */
final readonly class TokenAssuranceSweepResult
{
    /**
     * @param list<string> $errors
     * @param list<string> $unsupportedIssuers
     */
    public function __construct(
        public int $reclaimed,
        public int $retained,
        public int $unsupported,
        public int $errored,
        public array $errors,
        public array $unsupportedIssuers = [],
    ) {}
}
