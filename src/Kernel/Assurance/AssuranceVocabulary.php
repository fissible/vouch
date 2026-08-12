<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

/**
 * Names an assurance level from derived facts.
 *
 * Exists so the choice between NIST AAL names, OIDC acr URIs, and an
 * application-specific scale is configuration rather than a code change — the
 * name ends up in the public RFC 9470 acr_values string (spec §6.3), so it must
 * be swappable without touching derivation.
 */
interface AssuranceVocabulary
{
    public function name(AssuranceFacts $facts): string;
}
