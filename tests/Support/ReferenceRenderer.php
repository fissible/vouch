<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use Illuminate\Support\Facades\View;

/**
 * An INDEPENDENT consumer of the ScreenSpec contract.
 *
 * TEST-ONLY. Never published, never routeable, never registered in production.
 * It is not an adapter and not a preview of one — vouch-ui (Phase 3) owns
 * rendering, and this exists so the contract has been consumed by something
 * other than its own serializer before that phase inherits it.
 *
 * Asserting JSON shape would test the serializer against itself. §8.3 says the
 * second adapter is what reveals what the first baked in wrongly; with no first
 * adapter, nothing reveals anything until it is expensive to change.
 */
final class ReferenceRenderer
{
    /**
     * @param  array{result: string, handle: string|null, screen: array<string, mixed>}  $envelope
     */
    public function render(array $envelope): string
    {
        View::addNamespace('vouch-reference', __DIR__ . '/views');

        return View::make('vouch-reference::screen', [
            'screen' => $envelope['screen'],
            'handle' => $envelope['handle'],
        ])->render();
    }
}
