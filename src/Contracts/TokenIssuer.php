<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\TokenGrant;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;

interface TokenIssuer
{
    public function issuerKey(): string;

    public function supportsTransactionalIssuance(): bool;

    public function issue(ConnectionInterface $connection, TokenGrant $grant): IssuedToken;

    public function resolveForRequest(Request $request): ?ResolvedToken;

    public function revoke(string $tokenKey): void;
}
