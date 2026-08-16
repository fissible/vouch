<?php

declare(strict_types=1);

use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Database\Connection;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('builds interval arithmetic for every supported driver, with a bound placeholder', function (string $driver, string $expected): void {
    // A placeholder, not an interpolated int: every fragment is a true literal,
    // which is both the safe form and the only one the type system can vouch for.
    expect(DatabaseTime::deadlineSql($driver))->toBe($expected);
})->with([
    'mysql' => ['mysql', 'DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)'],
    'mariadb' => ['mariadb', 'DATE_ADD(CURRENT_TIMESTAMP, INTERVAL ? SECOND)'],
    'pgsql' => ['pgsql', "CURRENT_TIMESTAMP(0) + (? * INTERVAL '1 second')"],
    'sqlite' => ['sqlite', "datetime('now', printf('%+d seconds', ?))"],
]);

it('refuses an unrecognised driver rather than falling back', function (): void {
    /*
     * Falling back to an application timestamp would reintroduce clock drift
     * into a security window — silently, on whichever engine nobody tested.
     * Throwing is the whole point of centralising this.
     *
     * The driver NAME is asserted, not just the exception class. The standing
     * rule is to assert the message when the class is as broad as this one:
     * InvalidArgumentException is SPL and anything could raise it, so a
     * class-only assertion would stay green if an unrelated defect threw it
     * before this branch was ever reached — and would say nothing about whether
     * the operator can tell WHICH driver is unsupported, which is the only
     * actionable content the message carries.
     */
    expect(fn (): string => DatabaseTime::deadlineSql('oracle'))
        ->toThrow(InvalidArgumentException::class, 'oracle');
});

it('names both predicate and driver when a deadline comparison is unsupported', function (
    string $method,
    string $predicate,
): void {
    $connection = new Connection(
        static function (): PDO {
            throw new RuntimeException('The unsupported-driver test must not open a PDO connection.');
        },
        config: ['driver' => 'oracle'],
    );
    $time = new DatabaseTime($connection);
    $call = static fn (): string => match ($method) {
        'window-at-or-before' => $time->windowStartedAtAtOrBeforeDeadlineSql(),
        'window-after' => $time->windowStartedAtAfterDeadlineSql(),
        'lock-after' => $time->lockedUntilAfterDeadlineSql(),
        'created-after' => $time->createdAtAfterDeadlineSql(),
        'dispatch-at-or-before' => $time->dispatchedAtAtOrBeforeDeadlineSql(),
        default => throw new LogicException('Unknown DatabaseTime test method.'),
    };

    expect($call)->toThrow(
        InvalidArgumentException::class,
        'predicate "' . $predicate . '" for driver "oracle"',
    );
})->with([
    'window at or before' => ['window-at-or-before', 'window_started_at_at_or_before'],
    'window after' => ['window-after', 'window_started_at_after'],
    'lock after' => ['lock-after', 'locked_until_after'],
    'created after' => ['created-after', 'created_at_after'],
    'dispatch at or before' => ['dispatch-at-or-before', 'dispatched_at_at_or_before'],
]);

it('accepts the smallest positive database deadline and rejects non-positive values', function (): void {
    expect(app(DatabaseTime::class)->deadline(1))->toBeInstanceOf(DateTimeImmutable::class);

    foreach ([0, -1] as $seconds) {
        expect(fn (): DateTimeImmutable => app(DatabaseTime::class)->deadline($seconds))
            ->toThrow(InvalidArgumentException::class, 'at least one second');
    }
});

it('writes a deadline from the database clock, not the application clock', function (): void {
    /*
     * The decisive test for the preflight decision. Move the application clock
     * an hour into the past; a deadline written from it would land in the past
     * and the row would read as already expired. Written from the database
     * clock, it is still live.
     *
     * Without this, the deadline could be replaced by an application timestamp
     * and every other grace test would stay green.
     */
    Carbon::setTestNow(now()->subHour());

    app(\Fissible\Vouch\Recovery\GraceGuard::class)->start('host-clock', 7);

    expect(app(\Fissible\Vouch\Recovery\GraceGuard::class)->activeFor('host-clock'))
        ->toBeInstanceOf(\Fissible\Vouch\Models\AuthSession::class);
});
