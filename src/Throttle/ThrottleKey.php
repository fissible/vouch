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

    public function identifier(string $identifier, ?string $tenantId): string
    {
        return SessionBinding::forSegments(
            BindingDomain::ThrottleIdentifier,
            ...$this->scoped($tenantId, $this->identifiers->canonicalize($identifier)),
        );
    }

    public function recovery(string $identifier, ?string $tenantId): string
    {
        return SessionBinding::forSegments(
            BindingDomain::ThrottleRecovery,
            ...$this->scoped($tenantId, $this->identifiers->canonicalize($identifier)),
        );
    }

    public function ip(?string $ip, ?string $tenantId): ?string
    {
        $canonical = $this->ips->canonicalize($ip);

        if ($canonical === null) {
            return null;
        }

        $domain = filter_var($canonical, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
            ? BindingDomain::ThrottleIpV4
            : BindingDomain::ThrottleIpV6;

        return SessionBinding::forSegments(
            $domain,
            ...$this->scoped($tenantId, $canonical),
        );
    }

    public function ipIdentifier(
        ?string $ip,
        string $identifier,
        ?string $tenantId,
    ): ?string {
        $canonicalIp = $this->ips->canonicalize($ip);

        if ($canonicalIp === null) {
            return null;
        }

        return SessionBinding::forSegments(
            BindingDomain::ThrottleIpIdentifier,
            ...$this->scoped(
                $tenantId,
                $canonicalIp,
                $this->identifiers->canonicalize($identifier),
            ),
        );
    }

    public function tenant(?string $tenantId): string
    {
        return SessionBinding::forSegments(
            BindingDomain::ThrottleTenant,
            ...$this->tenantSegments($tenantId),
        );
    }

    public function global(): string
    {
        return SessionBinding::forSegments(BindingDomain::ThrottleGlobal, 'global');
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
