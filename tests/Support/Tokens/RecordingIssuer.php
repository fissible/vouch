<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Tokens;

use Closure;
use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\TokenGrant;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Http\Request;
use RuntimeException;
use Throwable;

/**
 * An issuer that records what it was asked to revoke, and can observe the
 * database at the moment it is asked.
 *
 * The observation hook is the only way to assert ORDER: whether Vouch's own
 * invalidation was already committed when the driver was called is not visible
 * from the end state, since both are gone either way.
 */
final class RecordingIssuer implements TokenIssuer
{
    /** @var list<string> */
    public array $revoked = [];

    /** @var list<string> Every key revoke() was called with, including failures. */
    public array $attempted = [];

    /** @var list<mixed> Whatever onRevoke returned, in call order. */
    public array $observed = [];

    /** @var Closure(): mixed|null */
    public ?Closure $onRevoke = null;

    private int $calls = 0;

    /**
     * @param Throwable|null $throwsOnRevoke Failure to raise from revoke().
     * @param int|null $throwOnCall Raise only on this 1-based call; null means every call.
     */
    public function __construct(
        private readonly string $key,
        private readonly ?Throwable $throwsOnRevoke = null,
        private readonly ?int $throwOnCall = null,
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
        throw new RuntimeException('This double records revocation; it does not issue.');
    }

    public function resolveForRequest(Request $request): ?ResolvedToken
    {
        return null;
    }

    public function revoke(string $tokenKey): void
    {
        $this->calls++;
        $this->attempted[] = $tokenKey;

        if ($this->onRevoke !== null) {
            $this->observed[] = ($this->onRevoke)();
        }

        if ($this->throwsOnRevoke !== null
            && ($this->throwOnCall === null || $this->throwOnCall === $this->calls)) {
            throw $this->throwsOnRevoke;
        }

        $this->revoked[] = $tokenKey;
    }
}
