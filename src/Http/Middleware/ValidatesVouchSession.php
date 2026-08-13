<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http\Middleware;

use Closure;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
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
 * A request with no vouch record passes through untouched: vouch does not own
 * every session, and refusing what it has no record of would break the host's
 * own authentication.
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

        if (! $record instanceof AuthSession) {
            return $next($request);
        }

        if ($record->revoked_at !== null) {
            $request->session()->invalidate();

            return redirect()->to('/');
        }

        return $next($request);
    }
}
