<?php

declare(strict_types=1);

namespace Fissible\Vouch\Notifications;

use DateTimeImmutable;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use RuntimeException;

/**
 * The default binding: fails loudly rather than dropping codes.
 *
 * Deliberately not a no-op and deliberately not a log writer. A no-op turns
 * "OTP is not wired up" into "OTP silently never arrives", and a log writer
 * would put a live authentication code into a log file, which is a credential
 * disclosure in the one place everybody greps.
 */
final class UnconfiguredOtpDelivery implements OtpDelivery
{
    public static function exception(): RuntimeException
    {
        return new RuntimeException(
            'No OTP delivery is configured. Bind Fissible\Vouch\Contracts\OtpDelivery to an '
            . 'implementation that sends mail or SMS. Vouch refuses to guess: a no-op would '
            . 'make codes silently never arrive, and logging the code would disclose a live '
            . 'credential.',
        );
    }

    public function deliver(AuthIdentifier $identifier, string $code, DateTimeImmutable $expiresAt): void
    {
        throw self::exception();
    }
}
