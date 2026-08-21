<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Contracts\CaptchaVerifier;
use Fissible\Vouch\Delivery\CaptchaDecision;
use Fissible\Vouch\Delivery\CaptchaRequest;

final class RecordingCaptchaVerifier implements CaptchaVerifier
{
    /** @var list<CaptchaRequest> */
    public array $requests = [];

    public CaptchaDecision $decision = CaptchaDecision::Failed;

    public function verify(CaptchaRequest $request): CaptchaDecision
    {
        $this->requests[] = $request;

        return $this->decision;
    }
}
