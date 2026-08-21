<?php

declare(strict_types=1);

namespace Fissible\Vouch\Contracts;

use Fissible\Vouch\Delivery\CaptchaDecision;
use Fissible\Vouch\Delivery\CaptchaRequest;

/**
 * Provider-independent CAPTCHA verification; vouch ships no provider.
 *
 * Implementations may throw when the upstream service is unavailable. The
 * flow treats that as a failed CAPTCHA and preserves the shared refusal.
 */
interface CaptchaVerifier
{
    public function verify(CaptchaRequest $request): CaptchaDecision;
}
