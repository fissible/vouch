<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Fissible\Vouch\Sessions\SessionLifecycle;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Resolves the request's session against auth_sessions on every request.
 *
 * Setting revoked_at changes nothing on its own — the host's cookie still
 * works. This read is what makes "all other sessions invalidated on password
 * change" a mechanism rather than a documented promise. One indexed lookup per
 * request is the correct price for that.
 *
 * An ownership marker keeps a missing row from turning an established session
 * into an unmanaged host session. Unmarked sessions still pass unless revoked:
 * vouch does not own every session, and recovery grace is also unmarked.
 *
 * Grace-bound sessions are handled by GraceGuard on vouch's own grace routes,
 * not here. They are never authenticated in the first place, so there is
 * nothing for this middleware to refuse — and refusing them here would block
 * the very routes grace exists to reach.
 */
final class ValidatesVouchSession
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! $request->hasSession()) {
            return $next($request);
        }

        $record = AuthSession::query()
            ->where('session_binding', SessionBinding::for($request->session()->getId(), BindingDomain::Session))
            ->first();

        if (($request->session()->exists(SessionLifecycle::OWNERSHIP_MARKER)
                && (! $record instanceof AuthSession
                    || $request->session()->get(SessionLifecycle::OWNERSHIP_MARKER) !== $record->id))
            || ($record instanceof AuthSession && $record->revoked_at !== null)) {
            $request->session()->invalidate();

            return redirect()->to('/');
        }

        return $next($request);
    }
}
