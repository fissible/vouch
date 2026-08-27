<?php

declare(strict_types=1);

namespace Fissible\Vouch\Authorization;

use Fissible\Vouch\Http\AssuranceComparator;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\Sessions\BindingDomain;
use Fissible\Vouch\Sessions\SessionBinding;
use Illuminate\Http\Request;

/** Deny-only fallback for checks that do reach Gate; middleware remains authoritative. */
final readonly class AssuranceGateHook
{
    public function __construct(private AssuranceRequirements $requirements, private AssuranceComparator $comparator) {}

    public function decide(mixed $user, string $ability, Request $request): ?bool
    {
        $required = $this->requirements->levelFor($ability);
        if ($required === null || $user === null || ! $request->hasSession()) {
            return null;
        }
        $identifier = is_object($user) && method_exists($user, 'getAuthIdentifier') ? $user->getAuthIdentifier() : null;
        if ($identifier === null) {
            return null;
        }
        $session = AuthSession::query()->where('session_binding', SessionBinding::for($request->session()->getId(), BindingDomain::Session))->first();
        if (! $session instanceof AuthSession || $session->user_id !== $identifier || ! $this->comparator->isSufficient($session, $required)) {
            return false;
        }
        return null;
    }
}
