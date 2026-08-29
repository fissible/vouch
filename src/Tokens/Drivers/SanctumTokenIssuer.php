<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens\Drivers;

use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Tokens\IssuedToken;
use Fissible\Vouch\Tokens\ResolvedToken;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenGrant;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use RuntimeException;
use Laravel\Sanctum\PersonalAccessToken;
use Laravel\Sanctum\Sanctum;
use Laravel\Sanctum\TransientToken;

/**
 * Sanctum adapter whose write path is deliberately independent of HasApiTokens.
 *
 * `createToken()` selects the tokenable model's default connection, so it can
 * commit outside Vouch's transaction. This adapter constructs the configured
 * token model on the caller's connection instead; an outer rollback therefore
 * removes every driver-owned write rather than leaving an unrecorded bearer.
 */
final class SanctumTokenIssuer implements TokenIssuer
{
    public function issuerKey(): string
    {
        return 'sanctum';
    }

    public function supportsTransactionalIssuance(): bool
    {
        return true;
    }

    public function issue(ConnectionInterface $connection, TokenGrant $grant): IssuedToken
    {
        $plainTextToken = $this->generateTokenString();
        $token = $this->configuredTokenModel();
        $tokenKey = $this->canonicalTokenKey($connection->table($token->getTable())->insertGetId([
            'tokenable_type' => $grant->subject->provider,
            'tokenable_id' => $grant->subject->id,
            'name' => $grant->name,
            'token' => hash('sha256', $plainTextToken),
            'abilities' => json_encode($grant->abilities, JSON_THROW_ON_ERROR),
            'created_at' => now(),
            'updated_at' => now(),
        ], $token->getKeyName()));

        return new IssuedToken(
            $this->issuerKey(),
            $tokenKey,
            $grant->subject,
            $tokenKey . '|' . $plainTextToken,
        );
    }

    public function resolveForRequest(Request $request): ?ResolvedToken
    {
        // Use Sanctum's actual guard precedence. Reading a bearer header here
        // would falsely claim requests where Sanctum selected a cookie actor.
        $principal = auth('sanctum')->user();

        if (! $principal instanceof Model || ! method_exists($principal, 'currentAccessToken')) {
            return null;
        }

        // HasApiTokens is a trait, not an interface the tokenable implements.
        // Checking the trait's interface would reject every genuine Sanctum
        // principal, so the guard above verifies the actual trait method.
        $accessToken = call_user_func([$principal, 'currentAccessToken']);

        if ($accessToken instanceof TransientToken || ! $accessToken instanceof PersonalAccessToken) {
            return null;
        }

        $tokenable = $accessToken->tokenable;

        if ($tokenable === null || ! $tokenable->is($principal)) {
            return null;
        }

        return new ResolvedToken(
            $this->issuerKey(),
            $this->canonicalTokenKey($accessToken->getKey()),
            SubjectKey::of($principal->getMorphClass(), $principal->getKey()),
            usable: true,
        );
    }

    public function revoke(string $tokenKey): void
    {
        $this->configuredTokenModel()->newQuery()->whereKey($tokenKey)->delete();
    }

    private function generateTokenString(): string
    {
        $entropy = Str::random(40);
        $prefix = config('sanctum.token_prefix', '');

        if (! is_string($prefix)) {
            throw new RuntimeException('Sanctum token_prefix must be a string.');
        }

        return $prefix . $entropy . hash('crc32b', $entropy);
    }

    private function configuredTokenModel(): PersonalAccessToken
    {
        $model = Sanctum::$personalAccessTokenModel;

        return new $model;
    }

    private function canonicalTokenKey(mixed $key): string
    {
        if ((! is_int($key) && ! is_string($key)) || (string) $key === '') {
            throw new RuntimeException('Sanctum persisted a token without a scalar key.');
        }

        return (string) $key;
    }
}
