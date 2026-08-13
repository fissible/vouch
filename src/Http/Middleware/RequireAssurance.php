<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/**
 * Interactive mode only. The RFC 9470 non-interactive rendering is 2.4's, and
 * shares this middleware's AssuranceComparator rather than reimplementing it.
 *
 * Grace sessions never reach here: they are not authenticated, so the host's own
 * auth middleware denies a protected route first. This is NOT grace's
 * containment mechanism and must never be relied on as one.
 */
final class RequireAssurance
{
    public function __construct(
        private readonly AssuranceComparator $comparator,
    ) {}

    public function handle(Request $request, Closure $next, string $required): Response
    {
        $session = AuthSession::query()
            ->where('session_binding', SessionBinding::for($request->session()->getId(), BindingDomain::Session))
            ->first();

        if ($this->comparator->isSufficient($session, $required)) {
            return $next($request);
        }

        $presentation = config('vouch.step_up.presentation_url');

        /*
         * FAIL CLOSED. 2.3 ships a JSON POST endpoint and no routeable
         * renderer, so there is nowhere safe to redirect by default -- a browser
         * sent to /vouch/auth issues a GET and receives 405. Guessing a
         * destination would be worse than refusing.
         */
        if (! is_string($presentation) || $presentation === '') {
            throw new RuntimeException(
                'Vouch requires vouch.step_up.presentation_url to be configured before a route '
                . 'can demand assurance. 2.3 ships no routeable step-up page; Phase 3 supplies '
                . 'the standard adapter. Refusing rather than redirecting to an endpoint that '
                . 'only answers POST.',
            );
        }

        /*
         * Built from the REQUEST's session, not a container-resolved one. In
         * production they are the same object; relying on that is a hidden
         * coupling that breaks the moment the middleware is invoked outside a
         * full request lifecycle -- and it would fail silently, writing the
         * target somewhere nothing later reads.
         *
         * The value is the URI the user was actually refused, never a client
         * parameter: a return_to input is an open-redirect primitive.
         */
        (new IntendedDestination($request->session()))->remember($request->getRequestUri());

        return redirect()->to($presentation);
    }
}
