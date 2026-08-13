<?php

declare(strict_types=1);

namespace Fissible\Vouch;

use Fissible\Vouch\Http\IntendedDestination;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use RuntimeException;

/**
 * The imperative entry point for demanding assurance (spec §7.5).
 *
 * `RequireAssurance` covers routes declaratively. This covers the cases that
 * are not a route boundary — a controller deciding mid-action that the next
 * step needs a stronger factor.
 *
 * Both paths store the return target the same way and fail closed the same way,
 * because two ways of starting a step-up would be two places for the
 * open-redirect rules to drift.
 */
final class Vouch
{
    /**
     * Send the caller to the step-up presentation, remembering where they were.
     *
     * @throws RuntimeException when no presentation URL is configured.
     */
    public static function stepUp(string $level, ?Request $request = null, ?string $intended = null): RedirectResponse
    {
        $request ??= request();
        $presentation = config('vouch.step_up.presentation_url');

        /*
         * FAIL CLOSED, identically to RequireAssurance. 2.3 ships no routeable
         * step-up page, so there is nowhere safe to guess: a browser sent to the
         * JSON endpoint issues a GET and receives 405.
         */
        if (! is_string($presentation) || $presentation === '') {
            throw new RuntimeException(
                'Vouch::stepUp(' . $level . ') requires vouch.step_up.presentation_url to be '
                . 'configured. 2.3 ships no routeable step-up page; Phase 3 supplies the '
                . 'standard adapter. Refusing rather than redirecting to an endpoint that '
                . 'only answers POST.',
            );
        }

        // Never a client-supplied return_to: that is an open-redirect primitive.
        (new IntendedDestination($request->session()))->remember($intended ?? $request->getRequestUri());

        return redirect()->to($presentation);
    }
}
