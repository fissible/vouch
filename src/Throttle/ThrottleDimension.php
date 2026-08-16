<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

/** Persisted domain label for an opaque, canonical throttle subject. */
enum ThrottleDimension: string
{
    case Identifier = 'identifier';
    case Recovery = 'recovery';
    case Issuance = 'issuance';
    case IpV4 = 'ipv4';
    case IpV6 = 'ipv6';
    case IpIdentifier = 'ip_identifier';
    case Tenant = 'tenant';
    case Global = 'global';
}
