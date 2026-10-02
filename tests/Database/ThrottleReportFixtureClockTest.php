<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Tests\Support\ThrottleReportFixture;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('writes no fixture timestamp that follows the app clock when the two disagree', function (): void {
    /*
     * #69's lexical guard is in ThrottleReportCommandTest, and this is the dependency
     * it cannot see. Three model creations in the fixture once omitted created_at and
     * updated_at, so Eloquent stamped them from Carbon -- an app-clock fixture
     * timestamp with no call to find. Giving the columns explicitly fixed it, and
     * nothing then held the fix in place: measured, deleting all six assignments left
     * every test in that file green, INCLUDING the one named for taking every
     * timestamp from one clock, while twenty-four stored values moved a full year.
     *
     * So the property is asserted where it lives, in the rows: the app clock is pushed
     * a year ahead of the database's and the fixture is seeded across the
     * disagreement. Anything that followed Carbon lands a year out, and anything that
     * did not does not move at all.
     *
     * Its own file, because the assertion needs to NAME Carbon and the guard in the
     * other file forbids that spelling there -- correctly, since a fixture has no
     * business reading the app clock. Writing it is a different act from reading it,
     * but the guard is lexical and cannot tell them apart, so the two live apart.
     *
     * A year, specifically. Large enough that no margin in the fixture could account
     * for it, and small enough to stay inside every column's range -- measured, a
     * twenty-year skew makes MySQL reject auth_attempts.updated_at outright with
     * error 1292, which would fail this test for the wrong reason.
     */
    $before = app(DatabaseTime::class)->current();

    try {
        // Carbon::setTestNow() rather than $this->travelTo(), which is this repo's
        // standing convention: PHPStan cannot resolve $this inside a Pest closure.
        Carbon::setTestNow(Carbon::instance($before)->addYear());

        ThrottleReportFixture::seed();
    } finally {
        Carbon::setTestNow();
    }

    $database = app(DatabaseTime::class)->current();

    /*
     * Compared as DATES, by string, over a five-day window around the database clock.
     * The fixture deliberately spreads itself a day either side -- a reservation
     * released a day back, an attempt expiring an hour ahead, window_started_at
     * rounded down to midnight -- so a tight bound would reject correct fixtures. The
     * window only has to separate "the database clock" from "a year away", and a date
     * prefix separates those completely.
     */
    $allowed = [];

    foreach ([-2, -1, 0, 1, 2] as $offset) {
        $shifted = $offset < 0
            ? $database->sub(new DateInterval('P' . abs($offset) . 'D'))
            : $database->add(new DateInterval('P' . $offset . 'D'));

        $allowed[] = $shifted->format('Y-m-d');
    }

    $checked = 0;

    foreach (ThrottleReportFixture::timestampColumns() as $table => $columns) {
        $rows = DB::table($table)->get();

        // The premise: there are rows to check. An empty table makes every assertion
        // below vacuous and this test would pass having proved nothing.
        expect($rows->count())->toBeGreaterThan(0);

        foreach ($rows as $row) {
            foreach ($columns as $column) {
                $value = $row->{$column} ?? null;

                if ($value === null) {
                    continue;
                }

                expect($allowed)->toContain(substr((string) $value, 0, 10));

                $checked++;
            }
        }
    }

    // And enough columns were reached that the loop is doing work rather than
    // skipping every value as null. Measured: the fixture writes 194 of them, the
    // same count an independent probe of these tables arrived at.
    expect($checked)->toBeGreaterThan(190);
});

/**
 * Every date-or-time column of every table the package owns, read from the SCHEMA.
 *
 * Deliberately not ThrottleReportFixture::timestampColumns(). That map is owned by the thing
 * under test, which makes it an oracle the fixture can quietly narrow: measured, writing a
 * machine-clock value to auth_challenges.consumed_at or to four of auth_challenge_outbox's
 * columns went unnoticed because the map does not list them, and deleting a column from the map
 * hid a machine-clock write outright.
 *
 * The fixture's own docblock argues the other way -- that a discovered list "would be built from
 * the same schema the fixture writes through and would therefore agree with it by construction".
 * That holds for the question it was written about, whether the fixture writes what it declares,
 * which a discovered list genuinely cannot answer. It does not hold here. The question here is
 * whether every value that reached a column came from the right clock, and the schema is defined
 * by the migrations in src/, not by the fixture -- so discovery reaches exactly the columns the
 * fixture never declared, which is where the misses were.
 *
 * Bounded, and the bounds are the package's own shape rather than a guess: tables the package
 * owns carry its prefix, and a timestamp it stores lives in a date or time typed column. A
 * timestamp serialized into a text or integer column, or held in a table outside the prefix,
 * is outside what this discovers -- the package has none, and a migration introducing one would
 * have to extend the filter here.
 *
 * @return array<string, list<string>>
 */
function skewAuditedColumns(): array
{
    $audited = [];

    foreach (Schema::getTableListing() as $listed) {
        // MySQL and PostgreSQL may qualify the name.
        $table = (string) preg_replace('/^.*\./', '', (string) $listed);

        if (! str_starts_with($table, 'auth_')) {
            continue;
        }

        $columns = [];

        foreach (Schema::getColumns($table) as $column) {
            if (in_array($column['type_name'], ['datetime', 'datetimetz', 'timestamp', 'timestamptz', 'date'], true)) {
                $columns[] = (string) $column['name'];
            }
        }

        if ($columns !== []) {
            sort($columns);
            $audited[$table] = $columns;
        }
    }

    ksort($audited);

    return $audited;
}

/**
 * Freeze the database clock at $clock, on the connection the fixture will use.
 *
 * Engine-specific, and the mechanisms are not equivalent.
 *
 * SQLite takes connection-local function overrides. Overriding a chosen few is not enough:
 * CURRENT_TIMESTAMP alone leaves datetime('now'), strftime(..., 'now'), a DEFAULT
 * CURRENT_TIMESTAMP column and a trigger all reading the real clock, and each of those is a
 * legitimate way to ask the DATABASE for the time -- so a narrow skew fails correct work. Every
 * clock-bearing function is overridden instead -- all seven SQLite documents, timediff() with
 * its two of them included, since leaving that one out let `datetime('2000-01-01',
 * timediff('now', '2000-01-01'))` read the live clock. The substitution covers the whole family
 * of spellings rather than the one a caller happened to use: the time value may be omitted
 * entirely, or written 'now', 'subsec' or 'subsecond', in any case.
 *
 * Everything else delegates to a second, unskewed SQLite connection, so semantics stay SQLite's
 * own rather than being reimplemented here: datetime('2026-10-02 12:34:56', 'start of day'),
 * datetime('0', 'unixepoch') and datetime('not a date', '+1 seconds') keep their real answers,
 * the last of them NULL. The one loss is subsecond precision, since the substituted literal is
 * whole seconds.
 *
 * MySQL takes SET SESSION timestamp, which fixes CURRENT_TIMESTAMP, NOW() and
 * DATE_ADD(CURRENT_TIMESTAMP, ...). Not SYSDATE(), which documents itself as ignoring it; a
 * fixture reading SYSDATE() would fail on MySQL. Nothing in the package spells it that way and
 * DatabaseTime cannot.
 *
 * PostgreSQL has no equivalent, which is why the case skips there: CURRENT_TIMESTAMP is a
 * keyword mapping to transaction_timestamp() rather than a function that can be shadowed, and
 * SET TIME ZONE moves the rendering by at most about fourteen hours. A stated limit.
 *
 * The overrides are NOT restored. A pass-through that returns the right value still is not the
 * builtin -- it carries none of the builtin's function flags, so an expression index or a
 * generated column over a date function is refused on that connection, and because each
 * delegated call runs its own statement it loses the per-statement clock snapshot that makes two
 * CURRENT_TIMESTAMP reads in one statement agree. Both were measured. So the caller discards the
 * connection instead, which is the only restoration that is actually complete.
 */
function freezeDatabaseClock(DateTimeImmutable $clock): void
{
    $connection = DB::connection();

    if ($connection->getDriverName() !== 'sqlite') {
        /*
         * The timezone first. Fixing the epoch does not fix how it renders, and the session
         * inherits whatever the server was configured with: measured, a connection on +01:00
         * returned 14:47:29 for a clock frozen at 13:47:29 UTC. The freeze states the timezone it
         * assumes rather than depending on the one it is given.
         */
        $connection->statement("SET SESSION time_zone = '+00:00'");
        $connection->statement('SET SESSION timestamp = ' . $clock->getTimestamp());

        return;
    }

    $pdo = $connection->getPdo();
    $unskewed = new PDO('sqlite::memory:');
    $literal = $clock->format('Y-m-d H:i:s');

    foreach ([
        // name => [delegate, which arguments are time values]
        'datetime' => ['datetime', [0]],
        'date' => ['date', [0]],
        'time' => ['time', [0]],
        'julianday' => ['julianday', [0]],
        'unixepoch' => ['unixepoch', [0]],
        'strftime' => ['strftime', [1]],
        'timediff' => ['timediff', [0, 1]],
        // The bare keywords take no arguments at all, so they are answered outright.
        'current_timestamp' => ['datetime', null],
        'current_date' => ['date', null],
        'current_time' => ['time', null],
    ] as $name => [$delegate, $positions]) {
        $pdo->sqliteCreateFunction($name, static function (mixed ...$arguments) use ($unskewed, $delegate, $positions, $literal): mixed {
            if ($positions === null) {
                $arguments = [$literal];
            } else {
                foreach ($positions as $position) {
                    if (! array_key_exists($position, $arguments)) {
                        // Omitted entirely: SQLite reads the current time.
                        $arguments[$position] = $literal;
                    } elseif (is_string($arguments[$position])
                        && in_array(strtolower($arguments[$position]), ['now', 'subsec', 'subsecond'], true)) {
                        $arguments[$position] = $literal;
                    }
                }

                ksort($arguments);
            }

            $statement = $unskewed->prepare(sprintf(
                'select %s(%s)',
                $delegate,
                implode(', ', array_fill(0, count($arguments), '?')),
            ));
            $statement->execute(array_values($arguments));

            return $statement->fetchColumn();
        }, -1);
    }
}

/**
 * Every stored value in the audited columns, grouped by column.
 *
 * No row identity, and that is the point. Three forms of this test tried to pair rows between the
 * two seedings -- by sorted value, by insertion order, then by a derived identity -- and each was
 * defeated in a new way: a column holding two shapes reorders, a fixture that reverses two inserts
 * breaks insertion order, an encrypted column cannot be part of an identity, and a foreign key's
 * rank follows insertion order rather than meaning. The mistake was upstream of all of them. The
 * property is about values, not rows: a timestamp either responded to the database clock or it did
 * not, whichever row happens to hold it. So the values are compared as a multiset and no row is
 * identified at all.
 *
 * @param  array<string, list<string>>  $audited
 * @return array<string, list<string>>
 */
function collectAuditedValues(array $audited): array
{
    $values = [];

    foreach ($audited as $table => $columns) {
        foreach (DB::table($table)->get() as $row) {
            foreach ($columns as $column) {
                $stored = $row->{$column} ?? null;

                if ($stored === null || $stored === '') {
                    continue;
                }

                $values[$table . '.' . $column][] = (string) $stored;
            }
        }
    }

    ksort($values);

    return $values;
}

/**
 * A stored timestamp as an instant: a date, optionally a time, optionally a fraction of a second.
 *
 * The fraction is kept rather than trimmed. A frozen database clock has none, so a value carrying
 * one took it from somewhere else -- measured, appending the machine's microseconds to an
 * otherwise correct value passed while the comparison stopped at whole seconds.
 *
 * Anchored at both ends, so anything else is reported rather than read as its own prefix. An
 * earlier form matched a prefix and so discarded a trailing timezone offset, which SQLite does
 * honour: a value ending '+00:31' was stored sixty seconds from where the comparison thought it
 * was, and passed.
 */
function parseStoredTimestamp(string $stored): ?DateTimeImmutable
{
    if (preg_match('/^(\d{4}-\d{2}-\d{2})(?:[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?)?$/', $stored, $matches) !== 1) {
        return null;
    }

    $parsed = DateTimeImmutable::createFromFormat(
        '!Y-m-d H:i:s.u',
        $matches[1] . ' ' . ($matches[2] ?? '00:00:00') . '.' . ($matches[3] ?? '0'),
        new DateTimeZone('UTC'),
    );

    return $parsed === false ? null : $parsed;
}

it('writes no fixture timestamp that follows the machine clock when the database clock disagrees', function (): void {
    /*
     * #97, the half the case above cannot reach.
     *
     * Skewing CARBON catches a fixture timestamp that followed the app clock -- the regression
     * that actually happened, Eloquent stamping created_at where the assignment was omitted. It
     * cannot catch a timestamp read straight from the machine clock, because Carbon's test-now
     * does not move time(), unixtojd(), IntlCalendar::getNow() or a Symfony DatePoint. The
     * lexical guard in ThrottleReportCommandTest covers those by scanning for spellings, and is
     * explicitly bounded: a denylist of names and classes has no closure when any installed
     * package may ship a clock of its own.
     *
     * This asks the database instead, and asks it twice.
     *
     * The fixture is seeded under one frozen database clock and then again under a second, and
     * every stored value must have moved by exactly the distance between them. That is a
     * difference, not a window, and it is what makes the check exact: a value read from the
     * machine clock does not move at all, and a value assembled from both clocks moves by only
     * the part it took from the database. An earlier form of this case compared each value
     * against a tolerance band around one skewed clock, and a band cannot do that -- measured, a
     * fixture writing the database's 'Y-m-d H:' with the machine's 'i:s' passed it on both
     * engines, and the band's own midnight exemption made the result depend on what time of day
     * the suite ran.
     *
     * Both cases are kept. They skew opposite clocks, fail for opposite reasons, and the Carbon
     * one pins a regression with a history.
     *
     * What a difference asserts is that every stored value RESPONDS to the database clock, which
     * is the property drift comes from. It is not the same as exclusive provenance, and the gap
     * is worth naming: a machine-derived quantity that is the same in both seedings cancels, so a
     * value written as "database clock plus gmdate('z') seconds" moves by exactly the right
     * amount and passes here. Measured. A component with second resolution may differ between the
     * two seedings and is then caught, but whether it does depends on whether the machine's
     * contribution changed, so being caught is not a property worth claiming.
     *
     * The engines differ in how much of this they betray, and the difference is in storage rather
     * than in the rule. SQLite keeps a value's text: a trailing timezone offset is rejected on its
     * shape, because the pattern that reads a stored value does not admit one, while a fraction of
     * a second IS admitted and so is governed by the paragraph above -- caught when it changes
     * between the seedings, cancelled when it does not. MySQL normalizes both as it stores them,
     * applying the offset and rounding the fraction into the second, so what remains is wrong only
     * by the amount absorbed and is caught on the same terms. Measured on both. Closing that from this side would mean recomputing the
     * fixture's own margins in the test, which couples the two and is how an earlier test in this
     * package came to reject correct work. It does not need closing from this side: the lexical
     * guard over the fixture's source is what sees gmdate(), and measured, it fails on that very
     * counter. The three instruments are complementary, and this is the one that does not depend
     * on knowing a clock's name.
     *
     * It also requires stored values to be instants or start-of-day truncations, which is what the
     * fixture writes. A value deliberately rounded to the minute, the hour or the end of a day
     * moves by none of the allowed distances and would need its own rule, and the failure reports
     * the expected and the observed second-seeding values, so that reads as a question about the
     * rule.
     *
     * Those rules are left out on purpose rather than for want of effort. Admitting a
     * minute-truncation distance would admit a value that takes everything but its seconds from
     * the database and its seconds from the machine, on the occasions the machine's seconds read
     * zero -- the truncation would look genuine and the distance would be right. Allowed distances
     * anchored to shapes the fixture actually writes is the stricter choice.
     *
     * A value's shape is read from the first seeding, which leaves one more edge. An instant whose
     * offset from the clock happens to equal the clock's own time of day lands exactly on midnight
     * there, is read as a truncation, and is held to the wrong distance. The clock's time of day is
     * 13:47:29 for that reason -- an unlikely thing for a margin to be -- and a fixture that did
     * use it would need the constant changed rather than the rule; the failure reports the expected
     * and the observed second-seeding values, so it reads as that question.
     *
     * For the same reason the arithmetic has to be in fixed units. Seconds, minutes, hours and
     * whole days all move a value by a constant, and start-of-day truncation by a constant too. A
     * CALENDAR offset does not: database-now minus one month lands a different number of seconds
     * away depending on which months the two clocks fall in, so admitting it would mean admitting
     * a range, and a range is what the previous form of this case was and what forged values
     * passed through. The fixture uses fixed units throughout.
     */
    if (DB::connection()->getDriverName() === 'pgsql') {
        $this->markTestSkipped('PostgreSQL has no session-level clock override; see freezeDatabaseClock().');
    }

    /*
     * Both clocks are literal, and in the past: literal so that nothing here depends on when the
     * suite runs -- not the hour, a date boundary, a DST transition or a leap day -- and in the
     * past so MySQL's session timestamp, which cannot be set beyond 2038, is never near its
     * ceiling. Deriving them from now did neither; it only moved the ceiling out.
     *
     * The distance between them is deliberately odd in every component -- days, hours, minutes
     * and seconds -- so a value following the database clock in some components and the machine
     * clock in others cannot move by the right amount. And neither sits at midnight, which is
     * what lets a value truncated to the start of a day be told apart from an instant.
     */
    $machine = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    $first = new DateTimeImmutable('2019-03-11 13:47:29', new DateTimeZone('UTC'));
    $second = $first->add(new DateInterval('P400DT7H13M11S'));

    /*
     * What a value that came from the database must do, and nothing else may. An instant moves the
     * whole distance between the clocks; a value truncated to the start of a day moves the whole
     * days in it.
     *
     * One truncated distance rather than two, deliberately. Truncating a value whose own offset
     * from the clock carries past midnight loses an extra day, so 401 days is also a legitimate
     * move -- for a value the fixture does not write, since everything it truncates is offset by
     * whole days. Admitting 401 as well was measured to open a hole exactly one day wide: a value
     * written as database-midnight plus a machine-derived number of days passed, because a machine
     * contribution that changed from zero days to one was indistinguishable from the extra day.
     * The narrower set is the stricter one, and a truncation the fixture does not currently write
     * will say so in a legible way rather than pass.
     */
    $instantShift = $second->getTimestamp() - $first->getTimestamp();
    $startOfDayShift = $second->setTime(0, 0)->getTimestamp() - $first->setTime(0, 0)->getTimestamp();

    expect($first->format('Y-m-d'))->not->toBe($machine->format('Y-m-d'));
    expect($startOfDayShift)->not->toBe($instantShift);
    expect($startOfDayShift)->toBeGreaterThan(0);

    $audited = skewAuditedColumns();
    $wipeOrder = array_reverse(array_keys(ThrottleReportFixture::timestampColumns()));

    try {
        $before = seedUnderFrozenClock($first, $audited);

        // Only the ORDER comes from the fixture's map, for the foreign keys. If the map misses a
        // table the fixture seeds, the emptiness check below says so.
        foreach ($wipeOrder as $table) {
            DB::table($table)->delete();
        }

        foreach (array_keys($audited) as $table) {
            expect(DB::table($table)->count())->toBe(0);
        }

        $after = seedUnderFrozenClock($second, $audited);
    } finally {
        /*
         * Discarding the connection is the restoration: see freezeDatabaseClock(). Everything
         * asserted below is already in PHP, so losing the rows with the transaction costs
         * nothing.
         */
        DB::purge(DB::connection()->getName());
    }

    expect(array_keys($after))->toBe(array_keys($before));

    $wrong = [];

    foreach ($before as $key => $values) {
        /*
         * Where each of the first seeding's values has to turn up in the second. One expected
         * value per stored value, decided by that value's own shape, so there is no matching to
         * get wrong -- a multiset in, a multiset out.
         */
        $expected = [];

        foreach ($values as $stored) {
            $from = parseStoredTimestamp($stored);

            if ($from === null) {
                $wrong[$key][] = 'unparsable: ' . $stored;

                continue;
            }

            $shift = $from->format('H:i:s.u') === '00:00:00.000000' ? $startOfDayShift : $instantShift;

            $expected[] = $from->add(new DateInterval('PT' . $shift . 'S'))->format('Y-m-d H:i:s.u');
        }

        // Canonicalized, so '2019-03-11 13:47:29' and the same instant written any other way
        // compare equal, and a fraction of a second never compares away.
        $actual = [];

        foreach ($after[$key] as $stored) {
            $to = parseStoredTimestamp($stored);
            $actual[] = $to === null ? 'unparsable: ' . $stored : $to->format('Y-m-d H:i:s.u');
        }

        sort($expected);
        sort($actual);

        if ($expected === $actual) {
            continue;
        }

        /*
         * Reported as what is missing and what turned up instead, rather than as two lists: a value
         * that did not move at all came from the machine clock, and one that moved part of the way
         * took part of itself from there.
         *
         * By count, not by set. array_diff() compares values and ignores how many times each
         * occurs, so a difference that is only in the multiplicities produced an empty report --
         * and since the report is what is asserted, the case passed on a difference it had already
         * detected. Measured: three values at offsets of six, seven and seven seconds against
         * expected offsets of six, six and seven passed, with all 194 values present.
         */
        $expectedCounts = array_count_values($expected);
        $actualCounts = array_count_values($actual);

        foreach ($expectedCounts as $value => $count) {
            $shortfall = $count - ($actualCounts[$value] ?? 0);

            if ($shortfall > 0) {
                $wrong[$key][] = 'expected ' . $value . ($shortfall > 1 ? ' x' . $shortfall : '');
            }
        }

        foreach ($actualCounts as $value => $count) {
            $surplus = $count - ($expectedCounts[$value] ?? 0);

            if ($surplus > 0) {
                $wrong[$key][] = 'found ' . $value . ($surplus > 1 ? ' x' . $surplus : '');
            }
        }

        // Unequal multisets always differ in some count, so the two loops above cannot both be
        // silent here. This is in case they are: a failure path that can fail to fail is worse
        // than no failure path, and that is exactly how the set-based version of this went wrong.
        if (($wrong[$key] ?? []) === []) {
            $wrong[$key][] = 'the two seedings differ and this report did not say how';
        }
    }

    /*
     * A value may also be here because the fixture asked the database for the time in a spelling
     * the freeze does not reach -- SYSDATE() on MySQL is the known one. That is a correct fixture
     * and a failing instrument, and it is named in freezeDatabaseClock() rather than left to be
     * rediscovered from this list.
     */
    expect($wrong)->toBe([]);

    /*
     * Vacuity, on two axes. Per column, because a total would let specific columns fall out
     * unnoticed; and in total, because a per-column set would let a single row's value fall out
     * while the column still had others. Measured: the fixture writes 194 values across these 27
     * columns.
     *
     * The column list is a minimum and the total is exact, so adding a column means updating the
     * total even though the column itself need not be listed. That is a fixture-shape contract
     * rather than an oversight: the alternative drops the only thing that notices a single value
     * going missing.
     */
    foreach ([
        'auth_attempts.created_at',
        'auth_attempts.expires_at',
        'auth_attempts.updated_at',
        'auth_challenge_outbox.created_at',
        'auth_challenge_outbox.delivered_at',
        'auth_challenge_outbox.expires_at',
        'auth_challenge_outbox.provider_attempted_at',
        'auth_challenge_outbox.undeliverable_at',
        'auth_challenge_outbox.updated_at',
        'auth_challenges.created_at',
        'auth_challenges.expires_at',
        'auth_challenges.updated_at',
        'auth_delivery_spend.created_at',
        'auth_delivery_spend.updated_at',
        'auth_delivery_spend.window_started_at',
        'auth_delivery_spend_reservations.created_at',
        'auth_delivery_spend_reservations.released_at',
        'auth_delivery_spend_reservations.window_started_at',
        'auth_throttle_counters.created_at',
        'auth_throttle_counters.updated_at',
        'auth_throttle_counters.window_started_at',
        'auth_throttle_ip_windows.created_at',
        'auth_throttle_ip_windows.updated_at',
        'auth_throttle_ip_windows.window_started_at',
        'auth_throttle_tuples.created_at',
        'auth_throttle_tuples.updated_at',
        'auth_throttle_tuples.window_started_at',
    ] as $required) {
        expect($before)->toHaveKey($required);
    }

    expect(array_sum(array_map('count', $before)))->toBe(194);
});

/**
 * Seed the fixture with the database clock frozen at $clock, and read back what it stored.
 *
 * @param  array<string, list<string>>  $audited
 * @return array<string, list<string>>
 */
function seedUnderFrozenClock(DateTimeImmutable $clock, array $audited): array
{
    freezeDatabaseClock($clock);

    /*
     * Premise: the freeze took, exactly. Both mechanisms stop the clock rather than offsetting
     * it, so this is an equality and not a tolerance -- and without it every comparison below
     * would hold on an unfrozen clock.
     */
    expect(app(DatabaseTime::class)->current()->format('Y-m-d H:i:s'))->toBe($clock->format('Y-m-d H:i:s'));

    ThrottleReportFixture::seed();

    return collectAuditedValues($audited);
}
