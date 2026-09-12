<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support\Http;

use Illuminate\Http\Request;
use RuntimeException;

/**
 * A request with no session that RECORDS every attempt to reach for one.
 *
 * The count and the exception serve different purposes, and the count is the
 * load-bearing half. Throwing alone is defeatable: the marker extends
 * RuntimeException, so an implementation that tried the session, caught the
 * throwable and returned the right redirect would look indistinguishable from
 * one that never touched it. The counter is recorded BEFORE the throw, so it
 * survives being caught.
 */
final class SessionlessProbeRequest extends Request
{
    public int $sessionTouches = 0;

    public static function for(string $uri = '/admin/settings'): self
    {
        $request = new self();
        $request->initialize([], [], [], [], [], ['REQUEST_URI' => $uri, 'REQUEST_METHOD' => 'GET']);

        return $request;
    }

    public function session(): never
    {
        $this->sessionTouches++;

        throw new RuntimeException('SessionTouched: the middleware reached for a session that does not exist.');
    }

    public function getSession(): never
    {
        $this->sessionTouches++;

        throw new RuntimeException('SessionTouched: the middleware reached for a session that does not exist.');
    }

    public function hasSession(bool $skipIfUninitialized = false): bool
    {
        return false;
    }
}
