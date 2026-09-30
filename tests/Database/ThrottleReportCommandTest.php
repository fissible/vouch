<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\OtpOutboxFailureReason;
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
        /*
         * Two seconds outside a 900-second window, and the tightness is the point.
         * Measured: this is the ONLY behavioural pin on that window anywhere in the
         * suite -- widen it to an hour and a reporter whose window is doubled to 1800
         * seconds passes every test that touches ThrottleReporter, all 87 of them.
         *
         * Tight is safe here because both ends come from the same clock, which is the
         * whole of what #69 was about. CURRENT_TIMESTAMP is the TRANSACTION timestamp
         * on PostgreSQL and MySQL and RefreshDatabase wraps each test in one, so
         * every DatabaseTime::current() call inside a test returns the identical
         * instant; on SQLite it advances, but only forward and only by whole seconds.
         */
        'window_started_at' => $active ? $now : $now->sub(new DateInterval('PT902S')),
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

/**
 * Seed one outbox row, with every timestamp from the DATABASE clock.
 *
 * The caller passes $expiresAt because that is the value under test; everything
 * else here is taken from the same clock the reporter compares against. This
 * function used to take three of its timestamps from Carbon's app clock while its
 * caller derived $expiresAt from the database's, which made a one-second margin
 * span two clock sources -- and a margin that small across two clocks says nothing
 * except how far apart the clocks are.
 */
function reportOutbox(string $status, DateTimeInterface $expiresAt, int $sequence): void
{
    $now = app(DatabaseTime::class)->current();

    $attempt = AuthAttempt::create([
        'handle' => str_pad("report-{$sequence}", 64, 'x'),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'bound_context' => str_repeat('r', 64),
        'expires_at' => $now->add(new DateInterval('PT1H')),
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
        'delivered_at' => $status === OtpOutboxStatus::Delivered->value ? $now : null,
        'provider_attempted_at' => $status === OtpOutboxStatus::Undeliverable->value ? $now : null,
        'undeliverable_at' => $status === OtpOutboxStatus::Undeliverable->value ? $now : null,
        'failure_reason' => $status === OtpOutboxStatus::Undeliverable->value
            ? OtpOutboxFailureReason::ProviderRejected->value
            : null,
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
    /*
     * ONE clock for the whole block. That is the fix; the margins stay tight.
     *
     * Rows 2 and 3 must read as already expired and rows 1 and 4 as still live,
     * against the DATABASE clock, which is what both the reporter and vouch:prune
     * compare with. These were written from Carbon's app clock three lines above a
     * $now taken from the database's -- and a margin measured in seconds across two
     * clock sources says nothing except how far apart the clocks are.
     *
     * Widening them was tried and reverted: measured, an hour either side lets four
     * mutants escape that a two-second margin catches -- the prune's outbox cutoff
     * moved thirty seconds either way, and the reporter's moved thirty seconds or
     * its window doubled. What made the old fixtures fragile was the second clock,
     * not the size of the gap.
     *
     * Measured on this machine: PostgreSQL's CURRENT_TIMESTAMP is within a
     * millisecond of PHP's, and MySQL reads about 200ms behind because it truncates
     * to seconds rather than because it drifts. So the file passed ten consecutive
     * PostgreSQL runs before this change too; what breaks it is a container clock
     * more than a second behind the host, which is ordinary after the host sleeps.
     */
    $now = app(DatabaseTime::class)->current();
    $live = $now->add(new DateInterval('PT60S'));
    $expired = $now->sub(new DateInterval('PT2S'));

    reportOutbox(OtpOutboxStatus::Pending->value, $live, 1);
    reportOutbox(OtpOutboxStatus::Pending->value, $expired, 2);
    reportOutbox(OtpOutboxStatus::Delivered->value, $expired, 3);
    reportOutbox(OtpOutboxStatus::Undeliverable->value, $live, 4);

    $old = $now->sub(new DateInterval('P1D'));
    DB::table('auth_delivery_spend')->insert([
        ['scope' => 'global', 'subject_digest' => str_pad('1', 64, 'd'), 'window_started_at' => $now->format('Y-m-d 00:00:00'), 'spent_minor' => 10, 'created_at' => $now, 'updated_at' => $now],
        ['scope' => 'tenant', 'subject_digest' => str_pad('2', 64, 'd'), 'window_started_at' => $now->format('Y-m-d 00:00:00'), 'spent_minor' => 0, 'created_at' => $now, 'updated_at' => $now],
    ]);
    DB::table('auth_delivery_spend_reservations')->insert([
        ['reservation_key' => str_pad(dechex(3), 64, 'c', STR_PAD_LEFT), 'scope' => 'global', 'amount_minor' => 10, 'window_started_at' => $now->format('Y-m-d 00:00:00'), 'created_at' => $now, 'released_at' => null],
        ['reservation_key' => str_pad(dechex(4), 64, 'c', STR_PAD_LEFT), 'scope' => 'tenant', 'amount_minor' => 20, 'window_started_at' => $now->format('Y-m-d 00:00:00'), 'created_at' => $now, 'released_at' => $now],
        ['reservation_key' => str_repeat('e', 64), 'scope' => 'tenant', 'amount_minor' => 30, 'window_started_at' => $old->format('Y-m-d 00:00:00'), 'created_at' => $old, 'released_at' => $now],
    ]);
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
            'undeliverable_reasons' => ['provider_rejected' => 1],
        ])
        ->and($report['economics'])->toBe([
            'current_scopes' => 2,
            'spent_minor' => 10,
            'reservations' => [
                'records' => 2,
                'gross_minor' => 30,
                'released_minor' => 20,
                'unreleased_minor' => 10,
                'delivered' => 1,
                'attempted_failed' => 1,
                'never_attempted_released' => 0,
                'missing_outbox' => 0,
            ],
        ])
        ->and($report['economics']['spent_minor'])
        ->toBe($report['economics']['reservations']['unreleased_minor']);

    $encoded = json_encode($report, JSON_THROW_ON_ERROR);
    $digests = array_merge(
        DB::table('auth_throttle_counters')->pluck('subject_digest')->all(),
        DB::table('auth_throttle_ip_windows')->pluck('ip_digest')->all(),
        DB::table('auth_throttle_tuples')->pluck('tuple_digest')->all(),
        DB::table('auth_delivery_spend')->pluck('subject_digest')->all(),
    );

    foreach ($digests as $digest) {
        expect($encoded)->not->toContain($digest);
    }

    expect($encoded)->not->toContain('report-secret')
        ->and($encoded)->not->toContain('subject_digest')
        ->and($encoded)->not->toContain('ip_digest')
        ->and($encoded)->not->toContain('tuple_digest');
});

it('counts released reservations that never reached a provider', function (): void {
    $sequence = 77;
    $now = app(DatabaseTime::class)->current();
    $reservationKey = str_pad(dechex($sequence), 64, 'c', STR_PAD_LEFT);

    reportOutbox(OtpOutboxStatus::Pending->value, $now->add(new DateInterval('PT1H')), $sequence);
    DB::table('auth_delivery_spend_reservations')->insert([
        'reservation_key' => $reservationKey,
        'scope' => 'global',
        'amount_minor' => 10,
        'window_started_at' => $now->format('Y-m-d 00:00:00'),
        'created_at' => $now,
        'released_at' => $now,
    ]);

    $economics = app(ThrottleReporter::class)->report()['economics'];

    expect($economics['reservations'])->toMatchArray([
        'records' => 1,
        'gross_minor' => 10,
        'released_minor' => 10,
        'unreleased_minor' => 0,
        'never_attempted_released' => 1,
    ]);
});

it('reports the complete top-level envelope and empty distributions', function (): void {
    $report = app(ThrottleReporter::class)->report();

    expect(array_keys($report))->toBe([
        'generated_at',
        'window_seconds',
        'dimensions',
        'outbox',
        'economics',
    ])->and($report['generated_at'])->toBeString()
        ->and($report['window_seconds'])->toBe(900)
        ->and($report['outbox'])->toBe([
            'pending' => 0,
            'overdue' => 0,
            'delivered' => 0,
            'undeliverable' => 0,
            'undeliverable_reasons' => [],
        ])->and($report['economics'])->toBe([
            'current_scopes' => 0,
            'spent_minor' => 0,
            'reservations' => [
                'records' => 0,
                'gross_minor' => 0,
                'released_minor' => 0,
                'unreleased_minor' => 0,
                'delivered' => 0,
                'attempted_failed' => 0,
                'never_attempted_released' => 0,
                'missing_outbox' => 0,
            ],
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

it('accepts each supported PDO driver aggregate type and normalizes it', function (): void {
    reportCounter('identifier', 1, 950);
    $row = DB::table('auth_throttle_counters')
        ->selectRaw('COUNT(*) AS aggregate_count')
        ->selectRaw('SUM(CASE WHEN count >= 0 THEN 1 ELSE 0 END) AS aggregate_sum')
        ->first();

    expect($row)->not->toBeNull();

    if ($row === null) {
        throw new RuntimeException('The aggregate type premise query returned no row.');
    }

    expect($row->aggregate_count)->toBeNumeric()
        ->and($row->aggregate_sum)->toBeNumeric()
        ->and((int) $row->aggregate_count)->toBe(1)
        ->and((int) $row->aggregate_sum)->toBe(1);
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
        'undeliverable_reasons' => ['provider_rejected' => 1],
    ])
        ->and(data_get($json, 'economics.spent_minor'))->toBe(10)
        ->and(data_get($json, 'economics.reservations.unreleased_minor'))->toBe(10)
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
        ->and($output)->toContain('OTP outbox: 1 pending, 1 overdue, 1 delivered, 1 undeliverable.')
        ->and($output)->toContain('Undeliverable reasons: {"provider_rejected":1}.')
        ->and($output)->toContain('Delivery spend: 2 current scope(s), 10 minor units spent; 2 reservation record(s), 10 minor units unreleased.');
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

    /*
     * An EXIT CODE, not a deletion count: 2 is CommandExit::DeliveryHealth, which
     * this command returns when it found undelivered outbox rows. What pins the
     * deletion -- rows 2 and 3 gone, rows 1 and 4 spared -- is the outbox block
     * below. Said here because the two read as one assertion and are not: measured,
     * a prune that classifies every row as delivered still deletes correctly and
     * fails on THIS line, while a prune with the wrong cutoff deletes the wrong rows
     * and fails on the block below.
     */
    expect(Artisan::call('vouch:prune'))->toBe(2);

    $report = app(ThrottleReporter::class)->report();

    expect($report['outbox'])->toBe([
        'pending' => 1,
        'overdue' => 0,
        'delivered' => 0,
        'undeliverable' => 1,
        'undeliverable_reasons' => ['provider_rejected' => 1],
    ]);
});

/**
 * App-clock spellings this file must not use, and the classes whose construction
 * reads the machine clock.
 *
 * @return array{0: list<string>, 1: list<string>}
 */
function appClockNames(): array
{
    return [
        ['now', 'today', 'tomorrow', 'yesterday', 'time', 'microtime', 'hrtime', 'gettimeofday', 'date_create', 'date_create_immutable', 'strtotime'],
        // 'date' for Laravel's Date facade, whose ::now() is the idiomatic app clock.
        // Only this guard's list: adding it to the arch guard's would change what it
        // reports about src/, which this change must not do.
        ['datetime', 'datetimeimmutable', 'carbon', 'carbonimmutable', 'date'],
    ];
}

it('takes every fixture timestamp in this file from one clock', function (): void {
    /*
     * #69, and the reason it is a guard rather than a comment: this is the fourth
     * time this project has shipped a test whose margin spanned two clocks. The
     * first three were PostgreSQL's CURRENT_TIMESTAMP(0) rounding where PHP
     * truncates; this one is plainer -- fixtures written from Carbon's app clock and
     * required to read as expired against the database's, three lines apart.
     *
     * Scoped to this file deliberately. Seventeen test files reference both clocks
     * and several exist precisely to measure the difference -- AttemptDeadlineClock
     * SourceTest, DeadlineClockSourceTest and OtpExpiryClockSourceTest all skew one
     * against the other on purpose -- so a suite-wide rule would reject the tests
     * that matter most. Here the app clock is never the right answer: everything
     * this file asserts is compared by the reporter or by vouch:prune against
     * DatabaseTime, so a fixture on any other clock measures the gap between them.
     */
    $source = file_get_contents(__FILE__);

    if (! is_string($source)) {
        throw new RuntimeException('This test file is unreadable.');
    }

    [$functions, $classes] = appClockNames();

    /*
     * The control, against a file that really does read the app clock, and this is
     * the second version of it. The first compared the needle against a string
     * built from the needle itself, which holds for ANY needle -- including one
     * matching nothing in PHP -- so it controlled nothing at all. Measured: with
     * that control in place and a real app-clock call planted in a fixture, a needle
     * of 'zzz(' passed.
     */
    $sibling = file_get_contents(__DIR__ . '/PruneCommandTest.php');

    if (! is_string($sibling)) {
        throw new RuntimeException('The control file is unreadable.');
    }

    expect(clockReadsIn($sibling, $functions, $classes))->not->toBe([]);

    // And the file really was scanned, so "no app clock" is not a statement about
    // an empty read.
    expect($source)->toContain('DatabaseTime');

    expect(clockReadsIn($source, $functions, $classes))->toBe([]);
});
