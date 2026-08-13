<?php

declare(strict_types=1);

use Fissible\Vouch\Http\AuthController;
use Fissible\Vouch\Recovery\GraceController;
use Illuminate\Support\Facades\Route;

Route::prefix(config()->string('vouch.routes.prefix'))
    ->middleware(config()->array('vouch.routes.middleware'))
    ->group(function (): void {
        // One endpoint. It begins when no handle is present and advances when
        // one is; the client never names the next step.
        Route::post('/auth', AuthController::class)->name('vouch.auth');

        // Separate, because these authorize from the grace record rather than
        // from a bound attempt.
        Route::post('/recovery/enroll', [GraceController::class, 'enroll'])->name('vouch.recovery.enroll');
        Route::post('/recovery/complete', [GraceController::class, 'complete'])->name('vouch.recovery.complete');
    });
