<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Sessions;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use RuntimeException;

/**
 * A host guard whose login fails.
 *
 * The completion protocol treats the guard login and the rebind that follows it
 * as one commit boundary, so the interesting case is a failure AFTER the record
 * exists. Everything else delegates to the real guard, so the double changes one
 * thing and the compensation path is exercised against genuine session state.
 */
final class FailingLoginGuard implements StatefulGuard
{
    public bool $loggedOut = false;

    /** @var Closure(): void|null Runs at login entry, before the failure. */
    public ?Closure $onLogin = null;

    /**
     * @param bool $throw When false, loginUsingId RETURNS false instead of
     *                    throwing — the failure mode a caller is most likely to
     *                    treat as success, since it is not an exception.
     */
    public function __construct(
        private readonly StatefulGuard $inner,
        private readonly bool $throw = true,
    ) {}

    public function loginUsingId($id, $remember = false)
    {
        /*
         * The hook exists so a test can observe the state AT LOGIN ENTRY. That
         * is where the record-before-guard ordering is falsifiable: a handler
         * that logged in first would reach here with no row written, and a
         * double that only threw could not tell the difference.
         */
        if ($this->onLogin !== null) {
            ($this->onLogin)();
        }

        if (! $this->throw) {
            return false;
        }

        throw new RuntimeException('the host guard refused the login');
    }

    public function logout(): void
    {
        $this->loggedOut = true;

        $this->inner->logout();
    }

    public function attempt(array $credentials = [], $remember = false)
    {
        return $this->inner->attempt($credentials, $remember);
    }

    public function once(array $credentials = [])
    {
        return $this->inner->once($credentials);
    }

    public function login(Authenticatable $user, $remember = false): void
    {
        $this->inner->login($user, $remember);
    }

    public function onceUsingId($id)
    {
        return $this->inner->onceUsingId($id);
    }

    public function viaRemember()
    {
        return $this->inner->viaRemember();
    }

    public function check(): bool
    {
        return $this->inner->check();
    }

    public function guest(): bool
    {
        return $this->inner->guest();
    }

    public function user()
    {
        return $this->inner->user();
    }

    public function id()
    {
        return $this->inner->id();
    }

    public function validate(array $credentials = []): bool
    {
        return $this->inner->validate($credentials);
    }

    public function hasUser(): bool
    {
        return $this->inner->hasUser();
    }

    public function setUser(Authenticatable $user): void
    {
        $this->inner->setUser($user);
    }
}
