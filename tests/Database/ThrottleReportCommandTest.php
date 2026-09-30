<?php

declare(strict_types=1);

use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Notifications\OtpOutboxFailureReason;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Tests\Support\ClockReads;
use Fissible\Vouch\Tests\Support\ThrottleReportFixture;
use Fissible\Vouch\Throttle\ThrottleReporter;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Console\Exception\InvalidOptionException;

uses(RefreshDatabase::class);

it('reports active aggregate distributions and configured threshold crossings without subjects', function (): void {
    ThrottleReportFixture::seed();

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

    ThrottleReportFixture::outbox(OtpOutboxStatus::Pending->value, $now->add(new DateInterval('PT1H')), $sequence);
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
    ThrottleReportFixture::counter('tenant', 2, 901);
    ThrottleReportFixture::counter('global', 2, 902);
    $dimensions = collect(app(ThrottleReporter::class)->report()['dimensions'])
        ->keyBy('dimension');

    expect(data_get($dimensions->get('tenant'), 'thresholds'))->toBe([
        ['name' => 'enforce', 'value' => 2, 'buckets_at_or_above' => 1],
    ])->and(data_get($dimensions->get('global'), 'thresholds'))->toBe([
        ['name' => 'enforce', 'value' => 3, 'buckets_at_or_above' => 0],
    ]);
});

it('accepts each supported PDO driver aggregate type and normalizes it', function (): void {
    ThrottleReportFixture::counter('identifier', 1, 950);
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
    ThrottleReportFixture::seed();

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
    ThrottleReportFixture::seed();

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
    /*
     * ASKED of PHP rather than written by hand, which is the same decision the arch
     * guard's own docblock records making after a hand-written list was wrong twice.
     * Mine was wrong on its first outing too: it omitted date(), gmdate() and
     * getdate(), and measured, `$now->setTimestamp((int) date('U') - 2)` passed the
     * guard while breaking three behavioural tests under a five-second clock offset.
     */
    $extension = get_extension_funcs('date');

    // Loudly rather than quietly: a guard that silently lost most of its list is
    // worse than one that is absent.
    expect($extension)->toBeArray();
    expect(count(is_array($extension) ? $extension : []))->toBeGreaterThan(20);

    $functions = array_map(
        static fn (string $name): string => strtolower($name),
        [
            ...(is_array($extension) ? $extension : []),
            // Not date-extension functions: Carbon's and Laravel's own spellings.
            'now', 'today', 'tomorrow', 'yesterday', 'microtime', 'hrtime', 'gettimeofday',
        ],
    );

    return [
        $functions,
        /*
         * The class half cannot be asked of PHP -- there is no "classes that read the
         * clock" list to enumerate -- so it stays hand-written, and a hand-written
         * list is exactly what was wrong twice before. What bounds the promise is
         * therefore stated rather than implied: this guard catches the spellings a
         * fixture in THIS codebase would plausibly use, not every way PHP can reach
         * machine time.
         *
         * The intl entries are here because they were missing and reachable:
         * measured, `IntlCalendar::getNow()` sourced an expired timestamp, passed the
         * guard, and broke three behavioural tests under a five-second database-clock
         * offset. 'date' is Laravel's Date facade, whose ::now() is the idiomatic app
         * clock. Only this guard's list -- the arch guard's is untouched, so what it
         * reports about src/ cannot change.
         */
        [
            'datetime', 'datetimeimmutable', 'carbon', 'carbonimmutable', 'date',
            'intlcalendar', 'intlgregoriancalendar', 'intldateformatter',
        ],
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
    /*
     * Both files, because the fixture moved out. It now lives in
     * Support\ThrottleReportFixture so a second test file can seed the same rows
     * without depending on this one having been loaded -- and a guard that scanned
     * only __FILE__ after that move would have been scanning the assertions while
     * the timestamps it exists to police sat in a file it never read.
     */
    $fixture = (new ReflectionClass(ThrottleReportFixture::class))->getFileName();

    if (! is_string($fixture)) {
        throw new RuntimeException('The throttle report fixture has no file to scan.');
    }

    $source = file_get_contents(__FILE__);
    $fixtureSource = file_get_contents($fixture);

    if (! is_string($source) || ! is_string($fixtureSource)) {
        throw new RuntimeException('This test file or its fixture is unreadable.');
    }

    $source .= $fixtureSource;

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

    expect(ClockReads::in($sibling, $functions, $classes))->not->toBe([]);

    // And both files really were scanned, so "no app clock" is not a statement about
    // an empty read. The fixture half is named separately: concatenation means a
    // single needle would be satisfied by either file alone.
    expect($source)->toContain('DatabaseTime');
    expect($fixtureSource)->toContain('DatabaseTime');
    expect($fixtureSource)->toContain('auth_challenge_outbox');

    expect(ClockReads::in($source, $functions, $classes))->toBe([]);
});
