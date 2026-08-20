<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

/** Provider-neutral CAPTCHA input; no account or resolved-user identity. */
final readonly class CaptchaRequest
{
    public function __construct(
        public string $token,
        public ?string $clientIp,
    ) {}
}
