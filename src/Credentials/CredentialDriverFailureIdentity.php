<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

/**
 * Identity-only projection of CredentialDriverFailure for caller results.
 *
 * Deliberately omits the internal diagnostic so a driver's exception text
 * cannot reach a caller through the returned failure identity.
 */
final readonly class CredentialDriverFailureIdentity
{
    public function __construct(public string $issuerKey, public string $tokenKey) {}

    /**
     * @param list<self> ...$passes
     * @return list<self>
     */
    public static function merge(array ...$passes): array
    {
        $identities = [];
        foreach ($passes as $failures) {
            foreach ($failures as $failure) {
                $identities[$failure->issuerKey][$failure->tokenKey] = new self(
                    $failure->issuerKey, $failure->tokenKey,
                );
            }
        }

        $merged = [];
        foreach ($identities as $tokens) {
            foreach ($tokens as $identity) {
                $merged[] = $identity;
            }
        }

        return $merged;
    }
}
