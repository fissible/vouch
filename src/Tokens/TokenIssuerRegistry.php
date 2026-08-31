<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use Fissible\Vouch\Contracts\TokenIssuer;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;
use RuntimeException;

/** @phpstan-type IssuerList list<TokenIssuer> */
final readonly class TokenIssuerRegistry
{
    /** @var IssuerList */
    private array $issuers;

    /** @param array<int, TokenIssuer> $issuers */
    public function __construct(array $issuers)
    {
        $this->issuers = array_values($issuers);
    }

    public function issue(string $issuerKey, ConnectionInterface $connection, TokenGrant $grant): IssuedToken
    {
        foreach ($this->issuers as $issuer) {
            if ($issuer->issuerKey() !== $issuerKey) {
                continue;
            }

            if ($grant->actor === ActorKind::Human && ! $issuer->supportsTransactionalIssuance()) {
                throw new RuntimeException(sprintf(
                    'Token issuer "%s" cannot issue assurance-bound human tokens transactionally.',
                    $issuerKey,
                ));
            }

            return $issuer->issue($connection, $grant);
        }

        throw new RuntimeException(sprintf('No token issuer is registered for key "%s".', $issuerKey));
    }

    public function resolveForRequest(Request $request): ?ResolvedToken
    {
        $claimed = null;

        foreach ($this->issuers as $issuer) {
            $resolved = $issuer->resolveForRequest($request);

            if ($resolved === null) {
                continue;
            }

            if ($claimed !== null) {
                throw new TokenIssuerCollision(sprintf(
                    'Token issuers "%s" and "%s" both claimed this request.',
                    $claimed->issuerKey,
                    $resolved->issuerKey,
                ));
            }

            $claimed = $resolved;
        }

        return $claimed;
    }

    /** @return IssuerList */
    public function transactionalIssuers(): array
    {
        return array_values(array_filter(
            $this->issuers,
            static fn (TokenIssuer $issuer): bool => $issuer->supportsTransactionalIssuance(),
        ));
    }

    /** @return IssuerList */
    public function issuers(): array
    {
        return $this->issuers;
    }
}
