<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Authorization\AssuranceRequirements;
use Fissible\Vouch\Authorization\RouteAbilityScanner;
use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Http\IntendedDestination;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

/** Primary assurance enforcement, before an earlier authorization grant can short-circuit Gate. */
final readonly class RequireAbilityAssurance
{
    public function __construct(private AssuranceRequirements $requirements, private RouteAbilityScanner $scanner, private AssuranceComparator $comparator) {}

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
        if ($session instanceof AuthSession && $session->user_id === $identifier && $this->comparator->isSufficient($session, $required)) {
            return $next($request);
        }
        $held = $session instanceof AuthSession ? $session->acr : null;
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
