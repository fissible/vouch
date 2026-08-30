<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionEvidence;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Interactive mode only. The RFC 9470 non-interactive rendering is 2.4's, and
 * uses the shared evidence comparator rather than reimplementing it.
 *
 * Grace sessions never reach here: they are not authenticated, so the host's own
 * auth middleware denies a protected route first. This is NOT grace's
 * containment mechanism and must never be relied on as one.
 */
final class RequireAssurance
{
    private readonly EvidenceComparator $evidenceComparator;

    private readonly \Psr\Clock\ClockInterface $clock;

    public function __construct(
        AssuranceComparator|EvidenceComparator|null $comparator = null,
        ?EvidenceComparator $evidenceComparator = null,
        ?\Psr\Clock\ClockInterface $clock = null,
    ) {
        // Retain the 0.1.1 construction seam. Route middleware is resolved by
        // the container, while consumers and the established direct-use tests
        // construct this with its original AssuranceComparator-only signature.
        // New construction may pass the evidence comparator directly; all
        // authorization decisions use that richer evidence path.
        $this->evidenceComparator = $comparator instanceof EvidenceComparator
            ? $comparator
            : ($evidenceComparator ?? app(EvidenceComparator::class));
        $this->clock = $clock ?? app(\Psr\Clock\ClockInterface::class);
    }

    public function handle(Request $request, Closure $next, string $required, ?string $maxAge = null): Response
    {
        $session = AuthSession::query()
            ->where('session_binding', SessionBinding::for($request->session()->getId(), BindingDomain::Session))
            ->first();

        $requirement = AssuranceRequirement::from($maxAge === null ? $required : ['level' => $required, 'max_age' => $maxAge]);
        if ($this->evidenceComparator->compare(SessionEvidence::read($session), $requirement, $this->clock, null)->outcome->isSufficient()) {
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

        return new RedirectResponse($presentation);
    }
}
