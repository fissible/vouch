<?php

declare(strict_types=1);

namespace Fissible\Vouch\Delivery;

/** Explicit CAPTCHA outcomes; an absent result is not success. */
enum CaptchaDecision
{
    case Passed;
    case Failed;
}
