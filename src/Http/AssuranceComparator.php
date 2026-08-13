<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

use Fissible\Vouch\Models\AuthSession;

/**
 * Decides whether a session's recorded assurance satisfies a requirement.
 *
 * Extracted rather than inlined into the redirect branch. Spec §6.3 specifies
 * one policy object with two renderings, and 2.4 adds the RFC 9470 response; a
 * comparison living inside the interactive branch would have to be moved then,
 * and the moved copy is where the two renderings drift apart.
 *
 * ORDERED comparison, never string equality: an aal2 session must satisfy a
 * route requiring aal1. Refusing a stronger session is a lockout that looks
 * like a security win.
 */
final readonly class AssuranceComparator
{
    /** @var list<string> Weakest first. */
    private const ORDER = ['aal0', 'aal1', 'aal2', 'aal3'];

    public function isSufficient(?AuthSession $session, string $required): bool
    {
        if (! $session instanceof AuthSession || $session->revoked_at !== null) {
            return false;
        }

        /*
         * A grace session is never sufficient for anything. It is also never
         * authenticated, so this should be unreachable -- fail closed anyway,
         * because "unreachable" is a claim about code that changes.
         */
        if ($session->isRecoveryGrace()) {
            return false;
        }

        $held = array_search($session->acr, self::ORDER, true);
        $want = array_search($required, self::ORDER, true);

        if ($held === false || $want === false) {
            return false;
        }

        return $held >= $want;
    }
}
