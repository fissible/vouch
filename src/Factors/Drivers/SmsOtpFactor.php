<?php

declare(strict_types=1);

namespace Fissible\Vouch\Factors\Drivers;

final readonly class SmsOtpFactor extends OtpFactor
{
    public function id(): string
    {
        return 'sms_otp';
    }

    protected function identifierType(): string
    {
        return 'phone';
    }
}
