<?php

declare(strict_types=1);

namespace Fissible\Vouch\Throttle;

use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;

/** Derives opaque, domain-separated keys for authentication throttle state. */
final readonly class ThrottleKey
{
    private const string TENANT_ABSENT = 'tenant.absent';

    private const string TENANT_PRESENT = 'tenant.present';

    public function __construct(
        private IdentifierCanonicalizer $identifiers,
        private IpCanonicalizer $ips,
    ) {}

    public function identifier(string $identifier, ?string $tenantId): ThrottleSubject
    {
        return $this->subject(
            ThrottleDimension::Identifier,
            BindingDomain::ThrottleIdentifier,
            $this->scoped($tenantId, $this->identifiers->canonicalize($identifier)),
        );
    }

    public function recovery(string $identifier, ?string $tenantId): ThrottleSubject
    {
        return $this->subject(
            ThrottleDimension::Recovery,
            BindingDomain::ThrottleRecovery,
            $this->scoped($tenantId, $this->identifiers->canonicalize($identifier)),
        );
    }

    public function issuance(string $identifier, ?string $tenantId): ThrottleSubject
    {
        return $this->subject(
            ThrottleDimension::Issuance,
            BindingDomain::ThrottleIssuance,
            $this->scoped($tenantId, $this->identifiers->canonicalize($identifier)),
        );
    }

    public function ceremony(string $identifier, ?string $tenantId): ThrottleSubject
    {
        return $this->subject(
            ThrottleDimension::Ceremony,
            BindingDomain::ThrottleCeremony,
            $this->scoped($tenantId, $this->identifiers->canonicalize($identifier)),
        );
    }

    public function ip(?string $ip, ?string $tenantId): ?ThrottleSubject
    {
        $canonical = $this->ips->canonicalize($ip);

        if ($canonical === null) {
            return null;
        }

        $isIpv4 = filter_var($canonical, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;

        return $this->subject(
            $isIpv4 ? ThrottleDimension::IpV4 : ThrottleDimension::IpV6,
            $isIpv4 ? BindingDomain::ThrottleIpV4 : BindingDomain::ThrottleIpV6,
            $this->scoped($tenantId, $canonical),
        );
    }

    public function ipIdentifier(
        ?string $ip,
        string $identifier,
        ?string $tenantId,
    ): ?ThrottleSubject {
        $canonicalIp = $this->ips->canonicalize($ip);

        if ($canonicalIp === null) {
            return null;
        }

        return $this->subject(
            ThrottleDimension::IpIdentifier,
            BindingDomain::ThrottleIpIdentifier,
            $this->scoped(
                $tenantId,
                $canonicalIp,
                $this->identifiers->canonicalize($identifier),
            ),
        );
    }

    public function tenant(?string $tenantId): ThrottleSubject
    {
        return $this->subject(
            ThrottleDimension::Tenant,
            BindingDomain::ThrottleTenant,
            $this->tenantSegments($tenantId),
        );
    }

    public function global(): ThrottleSubject
    {
        return $this->subject(
            ThrottleDimension::Global,
            BindingDomain::ThrottleGlobal,
            ['global'],
        );
    }

    /** @param list<string> $segments */
    private function subject(
        ThrottleDimension $dimension,
        BindingDomain $domain,
        array $segments,
    ): ThrottleSubject {
        return new ThrottleSubject(
            $dimension,
            SessionBinding::forSegments($domain, ...$segments),
        );
    }

    /** @return list<string> */
    private function tenantSegments(?string $tenantId): array
    {
        return $tenantId === null
            ? [self::TENANT_ABSENT]
            : [self::TENANT_PRESENT, $tenantId];
    }

    /** @return list<string> */
    private function scoped(?string $tenantId, string ...$subjectSegments): array
    {
        $segments = $this->tenantSegments($tenantId);

        foreach ($subjectSegments as $segment) {
            $segments[] = $segment;
        }

        return $segments;
    }
}
