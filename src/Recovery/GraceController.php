<?php

declare(strict_types=1);

namespace Fissible\Vouch\Recovery;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The constrained capability's own routes.
 *
 * These authorize from the GRACE RECORD, while /vouch/auth authorizes from the
 * bound attempt. Different authorization source, different route: collapsing
 * them would make one endpoint's guard depend on which of two states it
 * happened to be in.
 *
 * The host guard is never invoked here. A grace session stays anonymous, so
 * auth()->user() is null throughout and no host route is reachable with it.
 */
final readonly class GraceController
{
    public function __construct(
        private GraceGuard $grace,
    ) {}

    /** Enroll a real factor during grace. */
    public function enroll(Request $request): JsonResponse
    {
        /*
         * Re-resolved here, not trusted from request entry. A row live when the
         * request arrived can lapse before the mutation lands, and enrollment
         * is a mutation.
         */
        $this->grace->expireIfLapsed($request->session()->getId());

        if ($this->grace->activeFor($request->session()->getId()) === null) {
            return new JsonResponse(['result' => 'grace_expired'], 200);
        }

        return new JsonResponse(['result' => 'grace_active'], 200);
    }

    /** Complete recovery: fresh non-recovery evidence exchanges grace for a session. */
    public function complete(Request $request): JsonResponse
    {
        $this->grace->expireIfLapsed($request->session()->getId());

        if ($this->grace->activeFor($request->session()->getId()) === null) {
            return new JsonResponse(['result' => 'grace_expired'], 200);
        }

        return new JsonResponse(['result' => 'grace_active'], 200);
    }
}
