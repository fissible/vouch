<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tokens;

/**
 * Host-authorized token details.
 *
 * Abilities intentionally cross this boundary uninterpreted. Vouch evaluates
 * assurance for issuance; changing host authorization here would widen the
 * package's authority and make a narrow host grant unexpectedly usable.
 */
final readonly class TokenGrant
{
    /** @param list<string> $abilities */
    public function __construct(
        public SubjectKey $subject,
        public string $name,
        public array $abilities,
        public ?string $tenantId = null,
        public ActorKind $actor = ActorKind::Human,
    ) {}
}
