<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Support;

use DateInterval;
use DateTimeInterface;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Models\AuthChallenge;
use Fissible\Vouch\Models\AuthChallengeOutbox;
use Fissible\Vouch\Notifications\OtpOutboxFailureReason;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Support\Facades\DB;

/**
 * The throttle report's aggregate fixture, and every timestamp in it.
 *
 * Extracted from ThrottleReportCommandTest so a second test file can seed the same
 * rows without depending on that file having been loaded first -- a free function
 * declared in a test file exists only once Pest has collected it, so running the
 * other file alone would have failed on an undefined function.
 *
 * Every timestamp here comes from the DATABASE clock, which is what ThrottleReporter
 * and vouch:prune compare against. That is #69, and it is asserted two ways: a
 * lexical guard over this file's source, and a behavioural check that the persisted
 * rows do not follow the app clock when the two are pushed apart.
 */
final class ThrottleReportFixture
{
    /**
     * Every timestamp column this fixture writes, and the table holding it.
     *
     * Listed rather than discovered, because a discovered list would be built from
     * the same schema the fixture writes through and would therefore agree with it by
     * construction. A column added above and not added here is not checked -- the
     * honest limit of a list, and cheaper than trusting the schema to police itself.
     *
     * @return array<string, list<string>>
     */
    public static function timestampColumns(): array
    {
        return [
            'auth_throttle_counters' => ['window_started_at', 'created_at', 'updated_at'],
            'auth_throttle_ip_windows' => ['window_started_at', 'created_at', 'updated_at'],
            'auth_throttle_tuples' => ['window_started_at', 'created_at', 'updated_at'],
            'auth_attempts' => ['expires_at', 'created_at', 'updated_at'],
            'auth_challenges' => ['expires_at', 'created_at', 'updated_at'],
            'auth_challenge_outbox' => [
                'expires_at', 'delivered_at', 'provider_attempted_at', 'undeliverable_at',
                'created_at', 'updated_at',
            ],
            'auth_delivery_spend' => ['window_started_at', 'created_at', 'updated_at'],
            'auth_delivery_spend_reservations' => ['window_started_at', 'created_at', 'released_at'],
        ];
    }

    public static function counter(string $dimension, int $count, int $sequence, bool $active = true): void
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
             * whole of what #69 was about -- and because elapsed time moves the cutoff
             * AWAY from this row: it is excluded while now2 - now1 >= -2, and the clock
             * only advances.
             *
             * Not because the clock is frozen. An earlier version of this comment said
             * CURRENT_TIMESTAMP was the transaction timestamp on PostgreSQL and MySQL
             * both; measured, that is true only of PostgreSQL. Inside one transaction a
             * 2.1-second pause advanced MySQL's reading by two seconds and left
             * PostgreSQL's identical, and SQLite advances too. The margins hold on all
             * three for the reason above, not for the reason first given.
             */
            'window_started_at' => $active ? $now : $now->sub(new DateInterval('PT902S')),
            'count' => $count,
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    public static function ipWindow(string $dimension, int $markers, int $sequence): void
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
    public static function outbox(string $status, DateTimeInterface $expiresAt, int $sequence): void
    {
        $now = app(DatabaseTime::class)->current();

        /*
         * created_at and updated_at are given explicitly on all three models below.
         * Omitted, Eloquent stamps them from Carbon -- so the fixture kept an app-clock
         * dependency that no lexical guard can see, because there is no call to find.
         * Measured with Carbon a year ahead: the outbox row's created_at landed in 2027
         * while database time stayed in 2026, and at larger skews MySQL rejected
         * auth_attempts.updated_at outright with error 1292.
         */
        $attempt = AuthAttempt::create([
            'handle' => str_pad("report-{$sequence}", 64, 'x'),
            'state' => AttemptState::FactorPending,
            'version' => 1,
            'bound_context' => str_repeat('r', 64),
            'expires_at' => $now->add(new DateInterval('PT1H')),
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $challenge = AuthChallenge::create([
            'attempt_id' => $attempt->id,
            'factor_type' => 'password',
            'code_hash' => 'not-a-live-code',
            'expires_at' => $expiresAt,
            'created_at' => $now,
            'updated_at' => $now,
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
            'created_at' => $now,
            'updated_at' => $now,
        ]);
    }

    public static function seed(): void
    {
        foreach ([0, 1, 3, 7, 12, 42, 150, 301] as $sequence => $count) {
            self::counter('identifier', $count, 100 + $sequence);
        }

        self::counter('identifier', 999, 199, active: false);
        self::counter('recovery', 5, 200);
        self::counter('issuance', 5, 300);
        self::counter('tenant', 2, 400);
        self::counter('global', 3, 500);
        self::ipWindow('ipv4', 2, 600);
        self::ipWindow('ipv6', 30, 700);
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
         * mutants escape that these margins catch -- the prune's outbox cutoff moved
         * thirty seconds either way, and the reporter's moved thirty seconds either way.
         * What made the old fixtures fragile was the second clock, not the size of the
         * gap.
         *
         * The LIVE margin is twenty seconds rather than sixty for that reason, and the
         * correction is worth recording because the claim above was false at sixty. Both
         * cutoffs are `expires_at` against a single $now, so a cutoff shifted FORWARD is
         * only caught if it overtakes the live row: at +60s a +30s shift crossed nothing
         * and, measured, every one of the twenty-seven focused tests passed with either
         * cutoff advanced thirty seconds. Only the backward shift was ever caught. At
         * +20s both directions cross, and both mutants die.
         *
         * Twenty leaves eighteen seconds of slack against elapsed time, which is the
         * cost of tightening: elapsed time moves the EXPIRED margin away from its cutoff
         * (two seconds becomes four) but moves the LIVE margin toward it (twenty becomes
         * eighteen). The earlier justification here claimed only the favourable half.
         * What has to fit inside eighteen seconds is the gap between seeding a row and
         * asserting on it, which is one test rather than the whole file: measured, under
         * two seconds on the slowest engine, and ten consecutive runs on each of the
         * three engines showed no flake.
         *
         * Measured on this machine: PostgreSQL's CURRENT_TIMESTAMP is within a
         * millisecond of PHP's, and MySQL reads about 200ms behind because it truncates
         * to seconds rather than because it drifts. So the file passed ten consecutive
         * PostgreSQL runs before this change too; what breaks it is a container clock
         * more than a second behind the host, which is ordinary after the host sleeps.
         */
        $now = app(DatabaseTime::class)->current();
        $live = $now->add(new DateInterval('PT20S'));
        $expired = $now->sub(new DateInterval('PT2S'));

        self::outbox(OtpOutboxStatus::Pending->value, $live, 1);
        self::outbox(OtpOutboxStatus::Pending->value, $expired, 2);
        self::outbox(OtpOutboxStatus::Delivered->value, $expired, 3);
        self::outbox(OtpOutboxStatus::Undeliverable->value, $live, 4);

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
}
