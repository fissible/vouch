<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\DatabaseDeliveryEconomics;
use Fissible\Vouch\Delivery\DeliveryEconomicsConfiguration;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(DatabaseMigrations::class);

it('rethrows a non-contention query error instead of classifying it as retryable', function (): void {
    Schema::drop('auth_delivery_spend_reservations');

    $connection = DB::connection();
    $economics = new DatabaseDeliveryEconomics(
        $connection,
        new DatabaseTime($connection),
        app(ThrottleKey::class),
        new DeliveryEconomicsConfiguration(100, 100, ['US', 'CA']),
        new BoundedLockWait($connection),
        new LockContention(),
    );

    $economics->reserve(new DeliveryEconomicsRequest(
        'email_otp',
        'email',
        'tenant-a',
        null,
        10,
        false,
        str_repeat('q', 64),
    ));
})->throws(QueryException::class);
