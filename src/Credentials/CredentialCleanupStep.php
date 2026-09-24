<?php

declare(strict_types=1);

namespace Fissible\Vouch\Credentials;

/**
 * Post-mutation cleanup steps that failed after the credential change committed.
 *
 * SiblingRevocation means sibling sessions may still be live; EvidenceCleanup
 * means the current session's assurance may still include the removed credential.
 * Values deliberately carry no diagnostic: the original throwable is reported
 * separately so exception details do not reach callers through the result.
 */
enum CredentialCleanupStep: string
{
    case SiblingRevocation = 'sibling_revocation';
    case EvidenceCleanup = 'evidence_cleanup';
}
