<?php

declare(strict_types=1);

use Fissible\Vouch\Delivery\DatabaseDeliveryEconomics;
use Fissible\Vouch\Delivery\DeliveryEconomicsConfiguration;
use Fissible\Vouch\Delivery\DeliveryEconomicsRequest;
use Fissible\Vouch\Delivery\DeliveryReservationDecision;
use Fissible\Vouch\Support\BoundedLockWait;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Support\LockContention;
use Fissible\Vouch\Throttle\ThrottleKey;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

/** @param array{daily?: int|null, tenant?: int|null, countries?: list<string>} $overrides */
function deliveryEconomics(array $overrides = []): DatabaseDeliveryEconomics
{
    $configuration = new DeliveryEconomicsConfiguration(
        dailyCeilingMinor: $overrides['daily'] ?? 100,
        tenantCeilingMinor: $overrides['tenant'] ?? 60,
        smsAllowedCountries: $overrides['countries'] ?? ['US', 'CA'],
    );
    $connection = DB::connection();

    return new DatabaseDeliveryEconomics(
        $connection,
        new DatabaseTime($connection),
        app(ThrottleKey::class),
        $configuration,
        new BoundedLockWait($connection),
        new LockContention(),
    );
}

function deliveryRequest(
    int $cost = 10,
    ?string $tenant = 'tenant-a',
    string $channel = 'email',
    ?string $country = null,
    bool $decoy = false,
): DeliveryEconomicsRequest {
    return new DeliveryEconomicsRequest('email_otp', $channel, $tenant, $country, $cost, $decoy);
}

it('permits a decoy without creating or charging spend state', function (): void {
    expect(deliveryEconomics()->reserve(deliveryRequest(decoy: true)))
        ->toBe(DeliveryReservationDecision::Permitted)
        ->and(DB::table('auth_delivery_spend')->count())->toBe(0);
});

it('refuses an SMS country before creating spend state', function (): void {
    expect(deliveryEconomics()->reserve(deliveryRequest(channel: 'sms', country: 'GB')))
        ->toBe(DeliveryReservationDecision::CountryNotAllowed)
        ->and(DB::table('auth_delivery_spend')->count())->toBe(0);
});

it('atomically reserves both the daily and tenant ceilings', function (): void {
    expect(deliveryEconomics()->reserve(deliveryRequest()))
        ->toBe(DeliveryReservationDecision::Permitted);

    $rows = DB::table('auth_delivery_spend')->orderBy('scope')->get();

    expect($rows)->toHaveCount(2)
        ->and($rows->pluck('spent_minor')->all())->each->toBe(10);
});

it('rolls back the global reservation when the tenant ceiling refuses', function (): void {
    $economics = deliveryEconomics(['daily' => 100, 'tenant' => 15]);

    expect($economics->reserve(deliveryRequest(10)))->toBe(DeliveryReservationDecision::Permitted)
        ->and($economics->reserve(deliveryRequest(10)))->toBe(DeliveryReservationDecision::SpendCeiling);

    expect(DB::table('auth_delivery_spend')->where('scope', 'global')->value('spent_minor'))->toBe(10)
        ->and(DB::table('auth_delivery_spend')->where('scope', 'tenant')->value('spent_minor'))->toBe(10);
});

it('enforces the ceiling with an atomic predicate rather than a PHP increment', function (): void {
    $economics = deliveryEconomics(['daily' => 10, 'tenant' => null]);

    expect($economics->reserve(deliveryRequest(7)))->toBe(DeliveryReservationDecision::Permitted)
        ->and($economics->reserve(deliveryRequest(7)))->toBe(DeliveryReservationDecision::SpendCeiling)
        ->and(DB::table('auth_delivery_spend')->where('scope', 'global')->value('spent_minor'))->toBe(7);
});

it('keeps tenant absence and tenant names in separate spend buckets', function (): void {
    $economics = deliveryEconomics(['daily' => null, 'tenant' => 100]);

    expect($economics->reserve(deliveryRequest(10, null)))->toBe(DeliveryReservationDecision::Permitted)
        ->and($economics->reserve(deliveryRequest(10, '')))->toBe(DeliveryReservationDecision::Permitted);

    expect(DB::table('auth_delivery_spend')->where('scope', 'tenant')->count())->toBe(2);
});
