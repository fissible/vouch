<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Tests\Support\ThrottleReportFixture;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

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
