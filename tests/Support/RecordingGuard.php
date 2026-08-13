<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Models\AuthSession;
use Illuminate\Contracts\Auth\StatefulGuard;

/**
 * Records logins without needing a host user model.
 *
 * Vouch deliberately never references the host's authenticatable class, so the
 * real loginUsingId() depends on a provider the package does not own. What is
 * testable here -- and what matters -- is that the login happens AFTER the
 * session record exists, which this double captures by order of observation.
 *
 * Autoloaded rather than declared inside a test file: Pest includes test
 * files as it runs them, so a class declared in one is not reliably available
 * to another.
 */
final class RecordingGuard implements StatefulGuard
{
    /** @var list<mixed> */
    public array $loggedIn = [];

    /** @var list<int> */
    public array $sessionRowsAtLogin = [];

    public function loginUsingId($id, $remember = false): mixed
    {
        /** @var mixed $id */
        $this->loggedIn[] = $id;
        $this->sessionRowsAtLogin[] = AuthSession::count();

        // The contract returns Authenticatable|false. Vouch never reads the
        // return value, and this double owns no user model, so false is the
        // honest answer rather than a fabricated Authenticatable.
        return false;
    }

    public function check(): bool { return $this->loggedIn !== []; }
    public function guest(): bool { return ! $this->check(); }
    public function user(): mixed { return null; }
    public function id(): int|string|null
    {
        $first = $this->loggedIn[0] ?? null;

        return is_int($first) || is_string($first) ? $first : null;
    }
    /** @param  array<string, mixed>  $credentials */
    public function validate(array $credentials = []): bool { return false; }
    public function hasUser(): bool { return false; }
    public function setUser($user): static { return $this; }
    /** @param  array<string, mixed>  $credentials */
    public function attempt(array $credentials = [], $remember = false): bool { return false; }
    /** @param  array<string, mixed>  $credentials */
    public function once(array $credentials = []): bool { return false; }
    public function login($user, $remember = false): void {}
    public function onceUsingId($id): mixed { return false; }
    public function viaRemember(): bool { return false; }
    public function logout(): void {}
}
