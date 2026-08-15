<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\Factor;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Models\AuthCredential;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

/*
 * revoke() had no coverage on any driver: RemoveMethodCall on its single
 * `$credential->update(['disabled_at' => …])` survived, which means nothing
 * asserted that revoking disables anything.
 *
 * It is part of the Factor contract, so a host calling it to kill a compromised
 * credential would get a silent no-op -- the credential keeps authenticating and
 * the caller has every reason to believe it does not. Asserted across EVERY
 * registered driver rather than one, because the contract belongs to the
 * interface and each driver implements it separately.
 */

it('disables the credential it is asked to revoke', function (): void {
    $drivers = app(FactorRegistry::class)->all();

    expect($drivers)->not->toBeEmpty();

    foreach ($drivers as $driver) {
        expect($driver)->toBeInstanceOf(Factor::class);

        $credential = AuthCredential::create([
            'user_id' => 7,
            'type' => $driver->id(),
            'secret' => 'seed',
            'strength' => 'possession',
        ]);

        $driver->revoke($credential);

        expect($credential->refresh()->disabled_at)
            ->not->toBeNull("{$driver->id()} did not disable the credential");
    }
});

it('leaves other credentials alone when revoking one', function (): void {
    // The update is targeted at one row. Without the model's own key scoping it,
    // a revoke would disable every credential of that user.
    $driver = app(FactorRegistry::class)->all()[0];

    $target = AuthCredential::create([
        'user_id' => 7, 'type' => $driver->id(), 'secret' => 'a', 'strength' => 'possession',
    ]);
    $other = AuthCredential::create([
        'user_id' => 7, 'type' => $driver->id(), 'secret' => 'b', 'strength' => 'possession',
    ]);

    $driver->revoke($target);

    expect($target->refresh()->disabled_at)->not->toBeNull()
        ->and($other->refresh()->disabled_at)->toBeNull();
});
