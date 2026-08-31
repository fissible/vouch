<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tokens;

use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\TokenGrant;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;
use RuntimeException;

/**
 * An issuer that cannot say whether its tokens still exist.
 *
 * Deliberately does NOT implement ReportsTokenExistence. This is the case the
 * optional capability exists for: a third-party issuer over a remote authority
 * that has no cheap existence query. It must be skipped, never guessed at.
 */
final class SilentIssuer implements TokenIssuer
{
    public function __construct(private readonly string $key) {}

    public function issuerKey(): string
    {
        return $this->key;
    }

    public function supportsTransactionalIssuance(): bool
    {
        return false;
    }

    public function issue(ConnectionInterface $connection, TokenGrant $grant): IssuedToken
    {
        throw new RuntimeException('This double exists to be unanswerable, not to issue.');
    }

    public function resolveForRequest(Request $request): ?ResolvedToken
    {
        return null;
    }

    public function revoke(string $tokenKey): void {}
}
