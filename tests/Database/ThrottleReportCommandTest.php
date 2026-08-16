<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\ThrottleReporter;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Console\Exception\InvalidOptionException;

uses(RefreshDatabase::class);

function reportCounter(string $dimension, int $count, int $sequence, bool $active = true): void
{
    $now = app(DatabaseTime::class)->current();

    DB::table('auth_throttle_counters')->insert([
        'dimension' => $dimension,
        'subject_digest' => str_pad(dechex($sequence), 64, '0', STR_PAD_LEFT),
        'window_started_at' => $active ? $now : $now->sub(new DateInterval('PT901S')),
        'count' => $count,
        'created_at' => $now,
        'updated_at' => $now,
    ]);
}

function reportIpWindow(string $dimension, int $markers, int $sequence): void
{
    $now = app(DatabaseTime::class)->current();
    $parent = DB::table('auth_throttle_ip_windows')->insertGetId([
        'dimension' => $dimension,
        'ip_digest' => str_pad(dechex($sequence), 64, 'a', STR_PAD_LEFT),
        'window_started_at' => $now,
        'created_at' => $now,
        'updated_at' => $now,
    ]);

    for ($marker = 1; $marker <= $markers; $marker++) {
        DB::table('auth_throttle_tuples')->insert([
            'ip_window_id' => $parent,
            'window_started_at' => $now,
            'tuple_digest' => str_pad(dechex(($sequence * 1000) + $marker), 64, 'b', STR_PAD_LEFT),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }
}

function reportOutbox(string $status, DateTimeInterface $expiresAt, int $sequence): void
{
    $attempt = AuthAttempt::create([
        'handle' => str_pad("report-{$sequence}", 64, 'x'),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'bound_context' => str_repeat('r', 64),
        'expires_at' => now()->addHour(),
    ]);
    $challenge = AuthChallenge::create([
        'attempt_id' => $attempt->id,
        'factor_type' => 'password',
        'code_hash' => 'not-a-live-code',
        'expires_at' => $expiresAt,
    ]);

    AuthChallengeOutbox::create([
        'opaque_id' => str_pad(dechex($sequence), 64, 'c', STR_PAD_LEFT),
        'challenge_id' => $challenge->id,
        'payload' => $status === OtpOutboxStatus::Pending->value
            ? ['target' => null, 'code' => 'report-secret', 'decoy' => true]
            : null,
        'status' => $status,
        'expires_at' => $expiresAt,
        'delivered_at' => $status === OtpOutboxStatus::Delivered->value ? now() : null,
        'undeliverable_at' => $status === OtpOutboxStatus::Undeliverable->value ? now() : null,
    ]);
}

function seedAggregateReport(): void
{
    foreach ([0, 1, 3, 7, 12, 42, 150, 301] as $sequence => $count) {
        reportCounter('identifier', $count, 100 + $sequence);
    }

    reportCounter('identifier', 999, 199, active: false);
    reportCounter('recovery', 5, 200);
    reportCounter('issuance', 5, 300);
    reportCounter('tenant', 2, 400);
    reportCounter('global', 3, 500);
    reportIpWindow('ipv4', 2, 600);
    reportIpWindow('ipv6', 30, 700);
    reportOutbox(OtpOutboxStatus::Pending->value, now()->addMinute(), 1);
    reportOutbox(OtpOutboxStatus::Pending->value, now()->subSecond(), 2);
    reportOutbox(OtpOutboxStatus::Delivered->value, now()->subSecond(), 3);
    reportOutbox(OtpOutboxStatus::Undeliverable->value, now()->addMinute(), 4);
}

it('reports active aggregate distributions and configured threshold crossings without subjects', function (): void {
    seedAggregateReport();

    $report = app(ThrottleReporter::class)->report();
    $dimensions = collect($report['dimensions'])->keyBy('dimension');
    $identifier = $dimensions->get('identifier');
    $recovery = $dimensions->get('recovery');
    $issuance = $dimensions->get('issuance');
    $ipv4 = $dimensions->get('ipv4');
    $ipv6 = $dimensions->get('ipv6');
    $tenant = $dimensions->get('tenant');
    $global = $dimensions->get('global');

    expect($dimensions->keys()->all())->toBe([
        'identifier',
        'recovery',
        'issuance',
        'ipv4',
        'ipv6',
        'tenant',
        'global',
    ])
        ->and($identifier)->not->toBeNull()
        ->and(data_get($identifier, 'active_buckets'))->toBe(8)
        ->and(data_get($identifier, 'distribution'))->toBe([
            'zero' => 1,
            'one' => 1,
            'two_to_four' => 1,
            'five_to_nine' => 1,
            'ten_to_twenty_nine' => 1,
            'thirty_to_ninety_nine' => 1,
            'one_hundred_to_two_hundred_ninety_nine' => 1,
            'three_hundred_plus' => 1,
        ])
        ->and(data_get($identifier, 'thresholds'))->toBe([
            ['name' => 'backoff', 'value' => 5, 'buckets_at_or_above' => 5],
            ['name' => 'lock', 'value' => 10, 'buckets_at_or_above' => 4],
        ])
        ->and(data_get($recovery, 'active_buckets'))->toBe(1)
        ->and(data_get($recovery, 'thresholds'))->toBe([
            ['name' => 'backoff', 'value' => 5, 'buckets_at_or_above' => 1],
        ])
        ->and(data_get($issuance, 'active_buckets'))->toBe(1)
        ->and(data_get($issuance, 'thresholds'))->toBe([
            ['name' => 'limit', 'value' => 5, 'buckets_at_or_above' => 1],
        ])
        ->and(data_get($ipv4, 'active_buckets'))->toBe(1)
        ->and(data_get($ipv4, 'distribution.two_to_four'))->toBe(1)
        ->and(data_get($ipv4, 'thresholds'))->toBe([
            ['name' => 'observe', 'value' => 300, 'buckets_at_or_above' => 0],
        ])
        ->and(data_get($ipv6, 'active_buckets'))->toBe(1)
        ->and(data_get($ipv6, 'distribution.thirty_to_ninety_nine'))->toBe(1)
        ->and(data_get($ipv6, 'thresholds'))->toBe([
            ['name' => 'observe', 'value' => 30, 'buckets_at_or_above' => 1],
        ])
        ->and(data_get($tenant, 'active_buckets'))->toBe(1)
        ->and(data_get($tenant, 'thresholds'))->toBe([])
        ->and(data_get($global, 'active_buckets'))->toBe(1)
        ->and(data_get($global, 'thresholds'))->toBe([])
        ->and($report['outbox'])->toBe([
            'pending' => 1,
            'overdue' => 1,
            'delivered' => 1,
            'undeliverable' => 1,
        ]);

    $encoded = json_encode($report, JSON_THROW_ON_ERROR);
    $digests = array_merge(
        DB::table('auth_throttle_counters')->pluck('subject_digest')->all(),
        DB::table('auth_throttle_ip_windows')->pluck('ip_digest')->all(),
        DB::table('auth_throttle_tuples')->pluck('tuple_digest')->all(),
    );

    foreach ($digests as $digest) {
        expect($encoded)->not->toContain($digest);
    }

    expect($encoded)->not->toContain('report-secret')
        ->and($encoded)->not->toContain('subject_digest')
        ->and($encoded)->not->toContain('ip_digest')
        ->and($encoded)->not->toContain('tuple_digest');
});

it('reports the complete top-level envelope and empty distributions', function (): void {
    $report = app(ThrottleReporter::class)->report();

    expect(array_keys($report))->toBe([
        'generated_at',
        'window_seconds',
        'dimensions',
        'outbox',
    ])->and($report['generated_at'])->toBeString()
        ->and($report['window_seconds'])->toBe(900)
        ->and($report['outbox'])->toBe([
            'pending' => 0,
            'overdue' => 0,
            'delivered' => 0,
            'undeliverable' => 0,
        ]);

    foreach ($report['dimensions'] as $dimension) {
        expect($dimension['active_buckets'])->toBe(0)
            ->and($dimension['distribution'])->toBe([
                'zero' => 0,
                'one' => 0,
                'two_to_four' => 0,
                'five_to_nine' => 0,
                'ten_to_twenty_nine' => 0,
                'thirty_to_ninety_nine' => 0,
                'one_hundred_to_two_hundred_ninety_nine' => 0,
                'three_hundred_plus' => 0,
            ]);
    }
});

it('reports explicitly armed tenant and global thresholds', function (): void {
    config()->set('vouch.throttle.tenant', [
        'mode' => 'enforce',
        'enforce_at' => 2,
        'backoff_seconds' => 5,
    ]);
    config()->set('vouch.throttle.global', [
        'mode' => 'enforce',
        'enforce_at' => 3,
        'backoff_seconds' => 5,
    ]);
    app()->forgetInstance(\Fissible\Vouch\Throttle\ThrottleConfiguration::class);
    app()->forgetInstance(ThrottleReporter::class);
    reportCounter('tenant', 2, 901);
    reportCounter('global', 2, 902);
    $dimensions = collect(app(ThrottleReporter::class)->report()['dimensions'])
        ->keyBy('dimension');

    expect(data_get($dimensions->get('tenant'), 'thresholds'))->toBe([
        ['name' => 'enforce', 'value' => 2, 'buckets_at_or_above' => 1],
    ])->and(data_get($dimensions->get('global'), 'thresholds'))->toBe([
        ['name' => 'enforce', 'value' => 3, 'buckets_at_or_above' => 0],
    ]);
});

it('pins native aggregate integer types on every supported PDO driver', function (): void {
    reportCounter('identifier', 1, 950);
    $row = DB::table('auth_throttle_counters')
        ->selectRaw('COUNT(*) AS aggregate_count')
        ->selectRaw('SUM(CASE WHEN count >= 0 THEN 1 ELSE 0 END) AS aggregate_sum')
        ->first();

    expect($row)->not->toBeNull();

    if ($row === null) {
        throw new RuntimeException('The aggregate type premise query returned no row.');
    }

    expect($row->aggregate_count)->toBeInt()
        ->and($row->aggregate_sum)->toBeInt();
});

it('emits the same aggregate shape as JSON and human output', function (): void {
    seedAggregateReport();

    expect(Artisan::call('vouch:throttle:report', ['--json' => true]))->toBe(0);
    $json = json_decode(trim(Artisan::output()), true, flags: JSON_THROW_ON_ERROR);

    expect(data_get($json, 'outbox'))->toBe([
        'pending' => 1,
        'overdue' => 1,
        'delivered' => 1,
        'undeliverable' => 1,
    ])
        ->and(data_get($json, 'dimensions.0.dimension'))->toBe('identifier');

    $status = Artisan::call('vouch:throttle:report');
    $output = Artisan::output();

    expect($status)->toBe(0)
        ->and($output)->toContain('Dimension')
        ->and($output)->toContain('Active buckets')
        ->and($output)->toContain('Thresholds')
        ->and($output)->toContain('Distribution')
        ->and($output)->toContain('identifier')
        ->and($output)->toContain('8')
        ->and($output)->toContain('backoff=5 (5 crossed), lock=10 (4 crossed)')
        ->and($output)->toContain('"zero":1')
        ->and($output)->toContain('tenant')
        ->and($output)->toContain('none')
        ->and($output)->toContain('OTP outbox: 1 pending, 1 overdue, 1 delivered, 1 undeliverable.');
});

it('exposes neither candidate lookup options nor an underlying subject parameter', function (): void {
    $command = app(Kernel::class)->all()['vouch:throttle:report'];
    $options = array_keys($command->getDefinition()->getOptions());
    $parameters = (new ReflectionMethod(ThrottleReporter::class, 'report'))->getNumberOfParameters();

    expect($options)->toContain('json')
        ->and($options)->not->toContain('identifier')
        ->and($options)->not->toContain('ip')
        ->and($options)->not->toContain('tenant')
        ->and($options)->not->toContain('digest')
        ->and($options)->not->toContain('subject')
        ->and($parameters)->toBe(0);
});

it('rejects every subject-level lookup option at the command boundary', function (string $option): void {
    expect(fn (): int => Artisan::call('vouch:throttle:report', [$option => 'candidate']))
        ->toThrow(InvalidOptionException::class, 'option does not exist');
})->with([
    '--identifier',
    '--ip',
    '--tenant',
    '--digest',
    '--subject',
]);

it('removes expired aggregates from the report while leaving live rows visible', function (): void {
    seedAggregateReport();

    expect(Artisan::call('vouch:prune'))->toBe(2);

    $report = app(ThrottleReporter::class)->report();

    expect($report['outbox'])->toBe([
        'pending' => 1,
        'overdue' => 0,
        'delivered' => 0,
        'undeliverable' => 1,
    ]);
});
