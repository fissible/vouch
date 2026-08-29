<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

use JsonSerializable;

/**
 * A newly issued credential. Plaintext is available to the immediate caller
 * only; ordinary JSON and debugger rendering omit it so logging those paths
 * cannot turn a token issuance into a credential disclosure.
 */
final readonly class IssuedToken implements JsonSerializable
{
    public function __construct(
        public string $issuerKey,
        public string $tokenKey,
        public SubjectKey $subject,
        public string $plainText,
    ) {}

    /** @return array{issuerKey: string, tokenKey: string, subject: string} */
    public function jsonSerialize(): array
    {
        return [
            'issuerKey' => $this->issuerKey,
            'tokenKey' => $this->tokenKey,
            'subject' => $this->subject->toString(),
        ];
    }

    /** @return array{issuerKey: string, tokenKey: string, subject: string} */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }
}
