<?php

declare(strict_types=1);

namespace Fissible\Vouch\Http;

use Illuminate\Contracts\Session\Session;

/**
 * The post-step-up return target, held server-side.
 *
 * Never accepted from the client. A `return_to` parameter is an open-redirect
 * primitive: whatever validation guards it, the value still arrives from the
 * attacker. This stores the destination the user was actually refused, as a
 * same-origin origin-form path plus query — the part after the authority and
 * nothing more.
 *
 * A value failing validation is DISCARDED, never repaired. Sanitising a hostile
 * value is how the encoded and normalised authority forms survive: strip one
 * prefix and a later normalisation step reconstitutes it.
 */
final readonly class IntendedDestination
{
    private const KEY = 'vouch.step_up.intended';

    public function __construct(private Session $session) {}

    public function remember(string $candidate): void
    {
        $safe = $this->canonicalize($candidate);

        if ($safe === null) {
            $this->session->forget(self::KEY);

            return;
        }

        $this->session->put(self::KEY, $safe);
    }

    /** Read and clear, so a target cannot be replayed by a later step-up. */
    public function consume(): ?string
    {
        $value = $this->session->get(self::KEY);

        $this->session->forget(self::KEY);

        return is_string($value) ? $value : null;
    }

    /**
     * Allowlist. Anything not provably a same-origin origin-form path is null.
     */
    private function canonicalize(string $candidate): ?string
    {
        // A backslash is normalised to a forward slash by several parsers and
        // browsers, so `/\evil.example` becomes an authority in practice.
        if (str_contains($candidate, '\\')) {
            return null;
        }

        /*
         * Percent-encoded slashes and backslashes are rejected only in the PATH.
         * A later layer that decodes could otherwise reconstitute an authority
         * the check already passed — while `?q=a%2Fb` is an ordinary value and
         * must survive.
         */
        $path = strstr($candidate, '?', true);
        $path = $path === false ? $candidate : $path;

        if (preg_match('/%(2f|5c)/i', $path) === 1) {
            return null;
        }

        // Exactly one leading slash. `//host` and `///host` are protocol-relative.
        if (! str_starts_with($candidate, '/') || str_starts_with($candidate, '//')) {
            return null;
        }

        $parts = parse_url($candidate);

        if ($parts === false) {
            return null;
        }

        // Any authority component at all means it is not origin-form.
        foreach (['scheme', 'host', 'port', 'user', 'pass'] as $component) {
            if (isset($parts[$component])) {
                return null;
            }
        }

        $safe = $parts['path'] ?? null;

        if (! is_string($safe) || ! str_starts_with($safe, '/')) {
            return null;
        }

        return isset($parts['query']) ? $safe . '?' . $parts['query'] : $safe;
    }
}
