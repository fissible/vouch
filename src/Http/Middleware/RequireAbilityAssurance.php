<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Assurance\AssuranceRequirement;
use Fissible\Vouch\Assurance\EvidenceComparator;
use Fissible\Vouch\Authorization\AssuranceRequirements;
use Fissible\Vouch\Authorization\RouteAbilityScanner;
use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Kernel\Assurance\AssuranceVocabulary;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionEvidence;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/** Primary assurance enforcement, before an earlier authorization grant can short-circuit Gate. */
final readonly class RequireAbilityAssurance
{
    public function __construct(private AssuranceRequirements $requirements, private RouteAbilityScanner $scanner, private EvidenceComparator $evidenceComparator, private \Psr\Clock\ClockInterface $clock, private AssuranceVocabulary $vocabulary) {}

    public function handle(Request $request, Closure $next): Response
    {
        $route = $request->route();
        if (! $route instanceof \Illuminate\Routing\Route) {
            return $next($request);
        }
        $required = $this->requirements->strongestFor($this->scanner->abilitiesFor($route));
        $user = $request->user() ?? auth()->user();
        if ($required === null || $user === null) {
            return $next($request);
        }
        $session = null;
        if ($request->hasSession()) {
            $session = AuthSession::query()->where('session_binding', SessionBinding::for($request->session()->getId(), BindingDomain::Session))->first();
        }
        $identifier = $user->getAuthIdentifier();
        $read = SessionEvidence::read($session);
        if ($session instanceof AuthSession && $session->user_id === $identifier && $this->evidenceComparator->compare($read, AssuranceRequirement::from($required), $this->clock, null)->outcome->isSufficient()) {
            return $next($request);
        }
        $held = $read->evidence === null ? null : $this->vocabulary->name($read->evidence->facts());
        if ($request->expectsJson() || ! $request->hasSession()) {
            return new JsonResponse(['error' => 'insufficient_assurance', 'required' => $required, 'held' => $held], 403);
        }
        $presentation = config('vouch.step_up.presentation_url');
        if (! is_string($presentation) || $presentation === '') {
            throw new RuntimeException('Vouch requires vouch.step_up.presentation_url to be configured before a route can demand assurance.');
        }
        (new IntendedDestination($request->session()))->remember($request->getRequestUri());
        return new RedirectResponse($presentation);
    }
}
