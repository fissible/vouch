<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

final readonly class ResolvedToken
{
    public function __construct(
        public string $issuerKey,
        public string $tokenKey,
        public SubjectKey $subject,
        public bool $usable,
    ) {}
}
