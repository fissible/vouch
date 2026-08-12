<?php

declare(strict_types=1);

namespace Fissible\Vouch\Kernel\Enumeration;

/**
 * What actually happened, before posture filtering. Never serialised to a
 * response — ErrorShaper is the only consumer.
 */
enum Outcome: string
{
    case IdentifierKnown = 'identifier_known';
    case IdentifierUnknown = 'identifier_unknown';
    case CredentialRejected = 'credential_rejected';
    case Locked = 'locked';
}
