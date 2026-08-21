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

    public ?\Throwable $failure = null;

    public function verify(CaptchaRequest $request): CaptchaDecision
    {
        $this->requests[] = $request;

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->decision;
    }
}
