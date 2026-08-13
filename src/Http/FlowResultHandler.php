<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\Continuing;
use Fissible\Vouch\Flow\FlowResult;
use Fissible\Vouch\Flow\RecoveryGraceStarted;
use Fissible\Vouch\Flow\UnknownFlowResult;
use Fissible\Vouch\Recovery\GraceGuard;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;

/**
 * Routes a FlowResult to its side effect, then hands it back for serialization.
 *
 * This is the seam that keeps AuthFlow HTTP-free while giving session rotation
 * an explicit completion point. It is also the only place that logs into the
 * host guard, and it does so AFTER SessionLifecycle::establish() returns —
 * step 3 of the fail-closed protocol.
 *
 * An unhandled variant throws. Falling through would silently skip session
 * rotation on a successful authentication, leaving a user who appears logged in
 * with no record.
 */
final readonly class FlowResultHandler
{
    public function __construct(
        private SessionLifecycle $lifecycle,
        private GraceGuard $grace,
        private StatefulGuard $guard,
        private Session $session,
    ) {}

    public function handle(FlowResult $result): FlowResult
    {
        return match (true) {
            $result instanceof Continuing => $result,

            $result instanceof Authenticated => $this->establish($result),

            /*
             * Grace opens the capability and STOPS. The host guard is never
             * invoked and the anonymous session is retained as the bound
             * context — that is what makes a stolen recovery code a constrained
             * capability rather than an application session.
             */
            $result instanceof RecoveryGraceStarted => $this->openGrace($result),

            default => throw UnknownFlowResult::for($result),
        };
    }

    private function establish(Authenticated $result): Authenticated
    {
        $this->lifecycle->establish($result->success);

        // Step 3, and only now: the record exists.
        $this->guard->loginUsingId($result->success->userId);

        return $result;
    }

    private function openGrace(RecoveryGraceStarted $result): RecoveryGraceStarted
    {
        $this->grace->start($this->session->getId(), $result->userId);

        return $result;
    }
}
