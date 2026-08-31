<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tokens;

use Fissible\Vouch\Contracts\ReportsTokenExistence;
use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\TokenGrant;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;
use RuntimeException;
use Throwable;

/**
 * An issuer that can answer whether its tokens still exist.
 *
 * Records what it was ASKED as well as what it answered: the sweep's batching
 * and its scoping of returned keys are both properties of the question, not the
 * answer, and neither is observable from the resulting table alone.
 */
final class ExistenceReportingIssuer implements TokenIssuer, ReportsTokenExistence
{
    /** @var list<list<string>> */
    public array $askedBatches = [];

    /** @var list<string> */
    public array $revoked = [];

    /**
     * @param list<string> $existing Keys this issuer will report as still present.
     */
    public function __construct(
        private readonly string $key,
        private readonly array $existing,
        private readonly ?Throwable $throws = null,
    ) {}

    public function issuerKey(): string
    {
        return $this->key;
    }

    public function supportsTransactionalIssuance(): bool
    {
        return true;
    }

    public function issue(ConnectionInterface $connection, TokenGrant $grant): IssuedToken
    {
        throw new RuntimeException('This double exists to answer existence questions, not to issue.');
    }

    public function resolveForRequest(Request $request): ?ResolvedToken
    {
        return null;
    }

    public function revoke(string $tokenKey): void
    {
        $this->revoked[] = $tokenKey;
    }

    /**
     * @param list<string> $tokenKeys
     * @return list<string>
     */
    public function existingTokenKeys(array $tokenKeys): array
    {
        $this->askedBatches[] = $tokenKeys;

        if ($this->throws !== null) {
            throw $this->throws;
        }

        return $this->existing;
    }
}
