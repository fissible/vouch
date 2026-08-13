<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

use Fissible\Vouch\Flow\Authenticated;
use Fissible\Vouch\Flow\AuthFlow;
use Fissible\Vouch\Flow\FlowRequest;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * The whole HTTP surface for authentication: one action.
 *
 * Contains NO branching on AuthStep. If it grows a match on state, the boundary
 * has leaked and the client has started deciding what happens next.
 *
 * Every well-formed outcome returns 200. Status derives from the shaped result,
 * never the underlying cause — differing status by cause would defeat strict
 * posture via `curl -i` regardless of how carefully the body was filtered.
 * Transport failures (malformed JSON, CSRF, method) keep their own semantics
 * because they describe the request, not the account.
 */
final readonly class AuthController
{
    public function __construct(
        private AuthFlow $flow,
        private FlowResultHandler $handler,
        private FlowResultSerializer $serializer,
    ) {}

    public function __invoke(Request $request): JsonResponse
    {
        $handle = $request->input('handle');
        $action = $request->input('action');
        $input = $request->input('input');

        $result = $this->handler->handle($this->flow->advance(new FlowRequest(
            handle: is_string($handle) ? $handle : null,
            action: is_string($action) ? $action : null,
            input: is_array($input) ? $input : [],
            boundContext: SessionBinding::for($request->session()->getId(), BindingDomain::Attempt),
            clientIp: $request->ip(),
            clientUserAgent: $request->userAgent(),
        )));

        /*
         * Built from the REQUEST's session, matching RequireAssurance. A
         * container-resolved one is the same object in production, but relying
         * on that means the producer and the consumer are only assumed to share
         * a session -- and if they ever do not, the target is silently dropped
         * rather than reported.
         *
         * Consumed ONLY on the authenticated result, and exactly once.
         *
         * Consuming on every request would clear the target during the
         * intermediate begin and identify steps, so a user refused from a
         * protected page would silently land on the default instead of where
         * they were going -- and nothing would report it. Surviving consumption
         * is the opposite failure: a stored target replayed by a later step-up.
         */
        $returnTo = $result instanceof Authenticated
            ? (new IntendedDestination($request->session()))->consume()
                ?? config()->string('vouch.step_up.default_return')
            : null;

        return new JsonResponse($this->serializer->toArray($result, $returnTo));
    }
}
