<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

/** Redacted terminal causes; lifecycle status remains independently stable. */
enum OtpOutboxFailureReason: string
{
    case LegacyUnparseable = 'legacy_unparseable';
    case CountryNotAllowed = 'country_not_allowed';
    case SpendCeiling = 'spend_ceiling';
    case ProviderRejected = 'provider_rejected';
    case ProviderExhausted = 'provider_exhausted';
    case ExpiredUndelivered = 'expired_undelivered';
    case TargetUnavailable = 'target_unavailable';
}
