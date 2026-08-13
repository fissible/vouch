<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

final readonly class EmailOtpFactor extends OtpFactor
{
    public function id(): string
    {
        return 'email_otp';
    }

    protected function identifierType(): string
    {
        return 'email';
    }
}
