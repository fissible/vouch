<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Assurance;

/**
 * Conservative NIST-flavoured naming. Caps at aal2 by design.
 *
 * AAL3 additionally requires a hardware-based authenticator whose private key is
 * non-exportable — syncable passkeys are explicitly ineligible even though they
 * are phishing-resistant. AssuranceFacts carries no hardware-binding evidence, so
 * emitting aal3 here would assert something the kernel never observed. Phishing
 * resistance alone is an AAL2 property, not an AAL3 one.
 *
 * An application that does capture hardware binding (WebAuthn backup-eligibility
 * and backup-state flags, or attestation) can ship its own AssuranceVocabulary —
 * that extension point is why this class is not the interface.
 *
 * @see https://pages.nist.gov/800-63-4/sp800-63b/aal/
 */
final class NistAssuranceVocabulary implements AssuranceVocabulary, ReportsReachableLevels
{
    /** @return list<string> */
    public function reachableLevels(): array
    {
        return ['aal0', 'aal1', 'aal2'];
    }

    public function name(AssuranceFacts $facts): string
    {
        if ($facts->distinctCredentialCount === 0) {
            return 'aal0';
        }

        // One user-verified passkey is possession plus a biometric or PIN — two
        // factors on one credential. Counting credentials alone would understate it.
        if ($facts->distinctCredentialCount >= 2 || $facts->hasMultiFactorCredential) {
            return 'aal2';
        }

        return 'aal1';
    }
}
