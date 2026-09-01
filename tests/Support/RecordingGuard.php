<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Fissible\Vouch\Models\AuthSession;
use Illuminate\Contracts\Auth\Authenticatable;
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

    /**
     * Always succeeds. A double that could also fail would need a reason to,
     * and the failure paths have their own double in
     * tests/Support/Sessions/FailingLoginGuard.php.
     */
    public function loginUsingId($id, $remember = false): Authenticatable
    {
        /** @var mixed $id */
        $this->loggedIn[] = $id;
        $this->sessionRowsAtLogin[] = AuthSession::count();

        /*
         * The contract returns Authenticatable|false, and Vouch NOW READS IT:
         * issue #21 made a false return a login failure, because
         * SessionGuard::loginUsingId() returns false when its provider cannot
         * resolve the id and nothing else in the protocol would notice.
         *
         * The previous comment here said Vouch never read it, and returning
         * false was the honest answer for a double owning no user model. That
         * is no longer true in either half: false now MEANS failure, so a
         * double that returns it is asserting a failed login on every test that
         * uses it.
         *
         * A minimal Authenticatable is the honest answer instead. It is never
         * dereferenced — the handler only distinguishes false from not-false.
         */
        return new class($id) implements Authenticatable {
            public function __construct(private readonly mixed $id) {}

            public function getAuthIdentifierName(): string { return 'id'; }

            public function getAuthIdentifier(): mixed { return $this->id; }

            public function getAuthPasswordName(): string { return 'password'; }

            public function getAuthPassword(): string { return ''; }

            public function getRememberToken(): string { return ''; }

            public function setRememberToken($value): void {}

            public function getRememberTokenName(): string { return ''; }
        };
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
