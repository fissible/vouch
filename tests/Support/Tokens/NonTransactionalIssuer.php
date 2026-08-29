<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tokens;

use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;

/**
 * An issuer that cannot enlist in a caller's transaction — a remote or
 * HTTP-backed one, in practice.
 *
 * It exists so the refusal rule is tested rather than described: such a driver
 * is REFUSED for assurance-bound human issuance, never silently downgraded to
 * a weaker guarantee.
 */
final class NonTransactionalIssuer implements TokenIssuer
{
    public bool $issued = false;

    public function issuerKey(): string
    {
        return 'remote';
    }

    public function supportsTransactionalIssuance(): bool
    {
        return false;
    }

    public function issue(ConnectionInterface $connection, TokenGrant $grant): IssuedToken
    {
        $this->issued = true;

        return new IssuedToken($this->issuerKey(), 'remote-1', $grant->subject, 'plain');
    }

    public function resolveForRequest(Request $request): ?ResolvedToken
    {
        return null;
    }

    public function revoke(string $tokenKey): void {}
}
