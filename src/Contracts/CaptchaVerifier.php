<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Delivery\CaptchaDecision;
use Fissible\Vouch\Delivery\CaptchaRequest;

/** Provider-independent CAPTCHA verification; vouch ships no provider. */
interface CaptchaVerifier
{
    public function verify(CaptchaRequest $request): CaptchaDecision;
}
