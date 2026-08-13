<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

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
        private IntendedDestination $destination,
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

        return new JsonResponse($this->serializer->toArray($result, $this->destination->consume()));
    }
}
