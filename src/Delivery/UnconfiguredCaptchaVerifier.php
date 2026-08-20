<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

use Fissible\Vouch\Contracts\CaptchaVerifier;
use RuntimeException;

/** Fail closed until a host binds a provider-specific CAPTCHA verifier. */
final readonly class UnconfiguredCaptchaVerifier implements CaptchaVerifier
{
    public static function exception(): RuntimeException
    {
        return new RuntimeException(
            'No CAPTCHA verifier is configured. Bind '
            . 'Fissible\\Vouch\\Contracts\\CaptchaVerifier before enabling CAPTCHA escalation.',
        );
    }

    public function verify(CaptchaRequest $request): CaptchaDecision
    {
        throw self::exception();
    }
}
