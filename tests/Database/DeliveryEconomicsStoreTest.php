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
    ?string $reservationKey = null,
): DeliveryEconomicsRequest {
    static $sequence = 0;

    return new DeliveryEconomicsRequest(
        'email_otp',
        $channel,
        $tenant,
        $country,
        $cost,
        $decoy,
        $reservationKey ?? str_pad((string) ++$sequence, 64, '0', STR_PAD_LEFT),
    );
}

it('permits a decoy without creating or charging spend state', function (): void {
    expect(deliveryEconomics()->reserve(deliveryRequest(decoy: true)))
        ->toBe(DeliveryReservationDecision::Permitted)
        ->and(DB::table('auth_delivery_spend')->count())->toBe(0);
});

it('permits a zero-cost delivery without creating spend state', function (): void {
    expect(deliveryEconomics()->reserve(deliveryRequest(0)))
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

it('resets each spend scope when its daily window rolls over', function (): void {
    $economics = deliveryEconomics(['daily' => 100, 'tenant' => 100]);

    expect($economics->reserve(deliveryRequest(40)))->toBe(DeliveryReservationDecision::Permitted);

    $yesterday = now()->subDay()->startOfDay()->format('Y-m-d H:i:s');
    DB::table('auth_delivery_spend')->update([
        'window_started_at' => $yesterday,
        'spent_minor' => 40,
    ]);

    expect($economics->reserve(deliveryRequest(10)))->toBe(DeliveryReservationDecision::Permitted);

    $rows = DB::table('auth_delivery_spend')->orderBy('scope')->get();

    expect($rows)->toHaveCount(2)
        ->and($rows->pluck('spent_minor')->all())->each->toBe(10)
        ->and($rows->pluck('window_started_at')->all())
        ->each->toBe(now()->startOfDay()->format('Y-m-d H:i:s'));
});

it('keeps tenant absence and tenant names in separate spend buckets', function (): void {
    $economics = deliveryEconomics(['daily' => null, 'tenant' => 100]);

    expect($economics->reserve(deliveryRequest(10, null)))->toBe(DeliveryReservationDecision::Permitted)
        ->and($economics->reserve(deliveryRequest(10, '')))->toBe(DeliveryReservationDecision::Permitted);

    expect(DB::table('auth_delivery_spend')->where('scope', 'tenant')->count())->toBe(2);
});

it('records global and tenant spend even when both ceilings are observe-only', function (): void {
    $economics = deliveryEconomics(['daily' => null, 'tenant' => null]);

    expect($economics->reserve(deliveryRequest()))
        ->toBe(DeliveryReservationDecision::Permitted);

    $rows = DB::table('auth_delivery_spend')->get()->keyBy('scope');
    $global = $rows->get('global');
    $tenant = $rows->get('tenant');

    if (! is_object($global) || ! property_exists($global, 'spent_minor')
        || ! is_object($tenant) || ! property_exists($tenant, 'spent_minor')) {
        throw new RuntimeException('Expected global and tenant spend rows.');
    }

    expect($rows)->toHaveKeys(['global', 'tenant'])
        ->and((int) $global->spent_minor)->toBe(10)
        ->and((int) $tenant->spent_minor)->toBe(10);
});

it('does not charge a committed reservation twice', function (): void {
    $economics = deliveryEconomics(['daily' => null, 'tenant' => null]);
    $request = deliveryRequest(reservationKey: str_repeat('k', 64));

    expect($economics->reserve($request))->toBe(DeliveryReservationDecision::Permitted)
        ->and($economics->reserve($request))->toBe(DeliveryReservationDecision::Permitted);

    expect(DB::table('auth_delivery_spend')->where('scope', 'global')->value('spent_minor'))->toBe(10)
        ->and(DB::table('auth_delivery_spend')->where('scope', 'tenant')->value('spent_minor'))->toBe(10)
        ->and(DB::table('auth_delivery_spend_reservations')->count())->toBe(2);
});

it('releases a reservation when no provider delivery completed', function (): void {
    $economics = deliveryEconomics();
    $request = deliveryRequest(reservationKey: str_repeat('x', 64));

    expect($economics->reserve($request))->toBe(DeliveryReservationDecision::Permitted);

    $economics->release($request);

    $globalSpent = DB::table('auth_delivery_spend')->where('scope', 'global')->value('spent_minor');
    $tenantSpent = DB::table('auth_delivery_spend')->where('scope', 'tenant')->value('spent_minor');

    expect($globalSpent)->toBeInt()->toBe(0)
        ->and($tenantSpent)->toBeInt()->toBe(0)
        ->and(DB::table('auth_delivery_spend_reservations')->whereNotNull('released_at')->count())->toBe(2);
});

it('does not release an older-window reservation against the current spend window', function (): void {
    $economics = deliveryEconomics(['daily' => 100, 'tenant' => 100]);
    $oldRequest = deliveryRequest(reservationKey: str_repeat('o', 64));
    $currentRequest = deliveryRequest(reservationKey: str_repeat('c', 64));

    expect($economics->reserve($oldRequest))->toBe(DeliveryReservationDecision::Permitted)
        ->and($economics->reserve($currentRequest))->toBe(DeliveryReservationDecision::Permitted);

    DB::table('auth_delivery_spend_reservations')
        ->where('reservation_key', $oldRequest->reservationKey)
        ->update(['window_started_at' => now()->subDay()->startOfDay()->format('Y-m-d H:i:s')]);

    $economics->release($oldRequest);

    expect(DB::table('auth_delivery_spend')->where('scope', 'global')->value('spent_minor'))
        ->toBeInt()->toBe(20)
        ->and(DB::table('auth_delivery_spend_reservations')
            ->where('reservation_key', $oldRequest->reservationKey)
            ->whereNotNull('released_at')->count())
        ->toBe(2);
});

it('continues releasing other scopes when one reservation is already released', function (): void {
    $economics = deliveryEconomics();
    $request = deliveryRequest(reservationKey: str_repeat('r', 64));

    expect($economics->reserve($request))->toBe(DeliveryReservationDecision::Permitted);

    DB::table('auth_delivery_spend_reservations')
        ->where('reservation_key', $request->reservationKey)
        ->where('scope', 'global')
        ->update(['released_at' => now()]);

    $economics->release($request);

    expect(DB::table('auth_delivery_spend')->where('scope', 'global')->value('spent_minor'))
        ->toBeInt()->toBe(10)
        ->and(DB::table('auth_delivery_spend')->where('scope', 'tenant')->value('spent_minor'))
        ->toBeInt()->toBe(0);
});

it('continues releasing other scopes when one reservation is absent', function (): void {
    $economics = deliveryEconomics();
    $request = deliveryRequest(reservationKey: str_repeat('m', 64));

    expect($economics->reserve($request))->toBe(DeliveryReservationDecision::Permitted);

    DB::table('auth_delivery_spend_reservations')
        ->where('reservation_key', $request->reservationKey)
        ->where('scope', 'global')
        ->delete();

    $economics->release($request);

    expect(DB::table('auth_delivery_spend')->where('scope', 'tenant')->value('spent_minor'))
        ->toBeInt()->toBe(0);
});

it('marks a reservation released when its spend cannot be decremented', function (): void {
    $economics = deliveryEconomics();
    $request = deliveryRequest(reservationKey: str_repeat('u', 64));

    expect($economics->reserve($request))->toBe(DeliveryReservationDecision::Permitted);

    DB::table('auth_delivery_spend')->update(['spent_minor' => 0]);
    $economics->release($request);

    expect(DB::table('auth_delivery_spend_reservations')->whereNotNull('released_at')->count())->toBe(2);
});
