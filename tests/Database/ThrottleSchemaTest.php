<?php

declare(strict_types=1);

use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function throttleCounterRow(array $overrides = []): array
{
    return [
        'dimension' => 'identifier',
        'subject_digest' => str_repeat('a', 64),
        'window_started_at' => '2026-08-16 12:00:00',
        'count' => 1,
        'created_at' => '2026-08-16 12:00:00',
        'updated_at' => '2026-08-16 12:00:00',
        ...$overrides,
    ];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function throttleLockRow(array $overrides = []): array
{
    return [
        'subject_digest' => str_repeat('b', 64),
        'locked_until' => '2026-08-16 12:15:00',
        'created_at' => '2026-08-16 12:00:00',
        'updated_at' => '2026-08-16 12:00:00',
        ...$overrides,
    ];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function throttleIpWindowRow(array $overrides = []): array
{
    return [
        'dimension' => 'ipv4',
        'ip_digest' => str_repeat('c', 64),
        'window_started_at' => '2026-08-16 12:00:00',
        'created_at' => '2026-08-16 12:00:00',
        'updated_at' => '2026-08-16 12:00:00',
        ...$overrides,
    ];
}

/**
 * @param  array<string, mixed>  $overrides
 * @return array<string, mixed>
 */
function throttleTupleRow(int $parentId, array $overrides = []): array
{
    return [
        'ip_window_id' => $parentId,
        'window_started_at' => '2026-08-16 12:00:00',
        'tuple_digest' => str_repeat('d', 64),
        'created_at' => '2026-08-16 12:00:00',
        'updated_at' => '2026-08-16 12:00:00',
        ...$overrides,
    ];
}

it('creates only the four narrow throttle records', function (): void {
    expect(Schema::getColumnListing('auth_throttle_counters'))->toBe([
        'id',
        'dimension',
        'subject_digest',
        'window_started_at',
        'count',
        'created_at',
        'updated_at',
    ])->and(Schema::getColumnListing('auth_throttle_locks'))->toBe([
        'id',
        'subject_digest',
        'locked_until',
        'created_at',
        'updated_at',
    ])->and(Schema::getColumnListing('auth_throttle_ip_windows'))->toBe([
        'id',
        'dimension',
        'ip_digest',
        'window_started_at',
        'created_at',
        'updated_at',
    ])->and(Schema::getColumnListing('auth_throttle_tuples'))->toBe([
        'id',
        'ip_window_id',
        'window_started_at',
        'tuple_digest',
        'created_at',
        'updated_at',
    ]);

    $allColumns = array_merge(
        Schema::getColumnListing('auth_throttle_counters'),
        Schema::getColumnListing('auth_throttle_locks'),
        Schema::getColumnListing('auth_throttle_ip_windows'),
        Schema::getColumnListing('auth_throttle_tuples'),
    );

    expect(array_intersect($allColumns, [
        'identifier',
        'ip',
        'tenant_id',
        'user_id',
        'email',
        'debug_value',
    ]))->toBe([]);
});

it('indexes every lookup, lock, count and prune path by its real query prefix', function (): void {
    $expected = [
        'auth_throttle_counters' => [
            'auth_throttle_counter_subject_unique' => ['dimension', 'subject_digest'],
            'auth_throttle_counter_window_index' => ['window_started_at'],
            'auth_throttle_counter_updated_index' => ['updated_at'],
        ],
        'auth_throttle_locks' => [
            'auth_throttle_lock_subject_unique' => ['subject_digest'],
            'auth_throttle_lock_deadline_index' => ['locked_until'],
            'auth_throttle_lock_updated_index' => ['updated_at'],
        ],
        'auth_throttle_ip_windows' => [
            'auth_throttle_ip_window_subject_unique' => ['dimension', 'ip_digest'],
            'auth_throttle_ip_window_start_index' => ['window_started_at'],
        ],
        'auth_throttle_tuples' => [
            'auth_throttle_tuple_window_unique' => [
                'ip_window_id',
                'window_started_at',
                'tuple_digest',
            ],
            'auth_throttle_tuple_prune_index' => ['window_started_at'],
        ],
    ];

    foreach ($expected as $table => $indexes) {
        $actual = collect(Schema::getIndexes($table))->keyBy('name');

        foreach ($indexes as $name => $columns) {
            expect($actual->has($name))->toBeTrue("Missing index {$name} on {$table}.")
                ->and($actual->get($name)['columns'] ?? null)->toBe($columns);
        }
    }
});

it('declares every digest as a non-null 64-character protocol value', function (
    string $table,
    string $column,
    string $migration,
): void {
    $metadata = collect(Schema::getColumns($table))->firstWhere('name', $column);
    $source = file_get_contents(dirname(__DIR__, 2) . '/database/migrations/' . $migration);

    if (! is_string($source)) {
        throw new RuntimeException('Could not read the throttle migration under test.');
    }

    expect($metadata)->not->toBeNull()
        ->and($metadata['nullable'] ?? null)->toBeFalse()
        ->and($source)->toContain("->char('{$column}', 64)");

    /*
     * Laravel's SQLite grammar deliberately compiles char(N) to an
     * unconstrained varchar. The producer-side ThrottleKey test is therefore
     * the enforcement boundary on SQLite; MySQL and PostgreSQL preserve the
     * declared length in real column metadata and are asserted here.
     */
    if (DB::getDriverName() !== 'sqlite') {
        expect((string) ($metadata['type'] ?? ''))->toContain('64');
    }
})->with([
    'scalar subject' => [
        'auth_throttle_counters',
        'subject_digest',
        '2026_08_15_000001_create_auth_throttle_counters_table.php',
    ],
    'lock subject' => [
        'auth_throttle_locks',
        'subject_digest',
        '2026_08_15_000002_create_auth_throttle_locks_table.php',
    ],
    'IP subject' => [
        'auth_throttle_ip_windows',
        'ip_digest',
        '2026_08_15_000003_create_auth_throttle_ip_windows_table.php',
    ],
    'tuple subject' => [
        'auth_throttle_tuples',
        'tuple_digest',
        '2026_08_15_000004_create_auth_throttle_tuples_table.php',
    ],
]);

it('keeps operational timestamps non-null and without engine defaults', function (
    string $table,
    string $column,
): void {
    $metadata = collect(Schema::getColumns($table))->firstWhere('name', $column);

    if (! is_array($metadata)) {
        throw new RuntimeException("Missing {$table}.{$column} metadata.");
    }

    expect($metadata['nullable'])->toBeFalse()
        ->and(array_key_exists('default', $metadata))->toBeTrue()
        ->and($metadata['default'])->toBeNull();
})->with([
    ['auth_throttle_counters', 'created_at'],
    ['auth_throttle_counters', 'updated_at'],
    ['auth_throttle_locks', 'created_at'],
    ['auth_throttle_locks', 'updated_at'],
    ['auth_throttle_ip_windows', 'created_at'],
    ['auth_throttle_ip_windows', 'updated_at'],
    ['auth_throttle_tuples', 'created_at'],
    ['auth_throttle_tuples', 'updated_at'],
]);

it('requires every store-owned scalar value instead of inheriting a default', function (
    string $table,
    array $row,
    string $missing,
): void {
    unset($row[$missing]);

    expect(fn (): bool => DB::table($table)->insert($row))
        ->toThrow(QueryException::class);
})->with([
    'counter dimension' => ['auth_throttle_counters', throttleCounterRow(), 'dimension'],
    'counter digest' => ['auth_throttle_counters', throttleCounterRow(), 'subject_digest'],
    'counter window' => ['auth_throttle_counters', throttleCounterRow(), 'window_started_at'],
    'counter value' => ['auth_throttle_counters', throttleCounterRow(), 'count'],
    'lock digest' => ['auth_throttle_locks', throttleLockRow(), 'subject_digest'],
    'lock deadline' => ['auth_throttle_locks', throttleLockRow(), 'locked_until'],
    'IP dimension' => ['auth_throttle_ip_windows', throttleIpWindowRow(), 'dimension'],
    'IP digest' => ['auth_throttle_ip_windows', throttleIpWindowRow(), 'ip_digest'],
    'IP window' => ['auth_throttle_ip_windows', throttleIpWindowRow(), 'window_started_at'],
    'created timestamp' => ['auth_throttle_counters', throttleCounterRow(), 'created_at'],
    'updated timestamp' => ['auth_throttle_counters', throttleCounterRow(), 'updated_at'],
]);

it('refuses explicit null for every scalar protocol field', function (
    string $table,
    array $row,
    string $column,
): void {
    $row[$column] = null;

    expect(fn (): bool => DB::table($table)->insert($row))
        ->toThrow(QueryException::class);
})->with([
    'counter dimension' => ['auth_throttle_counters', throttleCounterRow(), 'dimension'],
    'counter digest' => ['auth_throttle_counters', throttleCounterRow(), 'subject_digest'],
    'counter window' => ['auth_throttle_counters', throttleCounterRow(), 'window_started_at'],
    'counter value' => ['auth_throttle_counters', throttleCounterRow(), 'count'],
    'lock digest' => ['auth_throttle_locks', throttleLockRow(), 'subject_digest'],
    'lock deadline' => ['auth_throttle_locks', throttleLockRow(), 'locked_until'],
    'IP dimension' => ['auth_throttle_ip_windows', throttleIpWindowRow(), 'dimension'],
    'IP digest' => ['auth_throttle_ip_windows', throttleIpWindowRow(), 'ip_digest'],
    'IP window' => ['auth_throttle_ip_windows', throttleIpWindowRow(), 'window_started_at'],
]);

it('stores a counter beyond the 32-bit range', function (): void {
    $large = 4_294_967_296;

    DB::table('auth_throttle_counters')->insert(throttleCounterRow(['count' => $large]));

    expect(DB::table('auth_throttle_counters')->value('count'))->toBe($large);
});

it('keeps one scalar row per dimension and digest', function (): void {
    DB::table('auth_throttle_counters')->insert(throttleCounterRow());

    expect(fn (): bool => DB::table('auth_throttle_counters')->insert(throttleCounterRow([
        'window_started_at' => '2026-08-16 12:15:00',
    ])))->toThrow(QueryException::class);
});

it('does not collide the same scalar digest across dimensions', function (): void {
    DB::table('auth_throttle_counters')->insert(throttleCounterRow());
    DB::table('auth_throttle_counters')->insert(throttleCounterRow(['dimension' => 'recovery']));

    expect(DB::table('auth_throttle_counters')->count())->toBe(2);
});

it('keeps one identifier lock per digest', function (): void {
    DB::table('auth_throttle_locks')->insert(throttleLockRow());

    expect(fn (): bool => DB::table('auth_throttle_locks')->insert(throttleLockRow([
        'locked_until' => '2026-08-16 12:30:00',
    ])))->toThrow(QueryException::class);
});

it('keeps one persistent parent per IP dimension and digest', function (): void {
    DB::table('auth_throttle_ip_windows')->insert(throttleIpWindowRow());

    expect(fn (): bool => DB::table('auth_throttle_ip_windows')->insert(throttleIpWindowRow([
        'window_started_at' => '2026-08-16 12:15:00',
    ])))->toThrow(QueryException::class);
});

it('lets IPv4 and IPv6 dimensions use the same digest independently', function (): void {
    DB::table('auth_throttle_ip_windows')->insert(throttleIpWindowRow());
    DB::table('auth_throttle_ip_windows')->insert(throttleIpWindowRow(['dimension' => 'ipv6']));

    expect(DB::table('auth_throttle_ip_windows')->count())->toBe(2);
});

it('deduplicates a tuple only inside its exact parent generation', function (): void {
    $parentId = (int) DB::table('auth_throttle_ip_windows')->insertGetId(throttleIpWindowRow());

    DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId));

    expect(fn (): bool => DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId)))
        ->toThrow(QueryException::class);
});

it('permits the same tuple in a later fixed-window generation', function (): void {
    $parentId = (int) DB::table('auth_throttle_ip_windows')->insertGetId(throttleIpWindowRow());

    DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId));
    DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId, [
        'window_started_at' => '2026-08-16 12:15:00',
    ]));

    expect(DB::table('auth_throttle_tuples')->count())->toBe(2);
});

it('counts distinct tuple digests through the indexed parent-generation prefix', function (): void {
    $parentId = (int) DB::table('auth_throttle_ip_windows')->insertGetId(throttleIpWindowRow());

    DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId));
    DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId, [
        'tuple_digest' => str_repeat('e', 64),
    ]));

    $index = collect(Schema::getIndexes('auth_throttle_tuples'))
        ->firstWhere('name', 'auth_throttle_tuple_window_unique');

    expect(DB::table('auth_throttle_tuples')
        ->where('ip_window_id', $parentId)
        ->where('window_started_at', '2026-08-16 12:00:00')
        ->count())->toBe(2)
        ->and(array_slice($index['columns'] ?? [], 0, 2))
        ->toBe(['ip_window_id', 'window_started_at']);
});

it('cascades markers only when their serialization parent is deliberately deleted', function (): void {
    $parentId = (int) DB::table('auth_throttle_ip_windows')->insertGetId(throttleIpWindowRow());
    DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId));

    DB::table('auth_throttle_ip_windows')->where('id', $parentId)->delete();

    expect(DB::table('auth_throttle_tuples')->count())->toBe(0);
});

it('prunes expired markers without deleting their persistent parent', function (): void {
    $parentId = (int) DB::table('auth_throttle_ip_windows')->insertGetId(throttleIpWindowRow());
    DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId));

    DB::table('auth_throttle_tuples')
        ->where('window_started_at', '<=', '2026-08-16 12:00:00')
        ->delete();

    expect(DB::table('auth_throttle_tuples')->count())->toBe(0)
        ->and(DB::table('auth_throttle_ip_windows')->where('id', $parentId)->exists())
        ->toBeTrue();
});

it('refuses a tuple whose parent does not exist', function (): void {
    expect(fn (): bool => DB::table('auth_throttle_tuples')->insert(throttleTupleRow(999_999)))
        ->toThrow(QueryException::class);
});

it('refuses a tuple with a null generation or digest', function (string $column): void {
    $parentId = (int) DB::table('auth_throttle_ip_windows')->insertGetId(throttleIpWindowRow());

    expect(fn (): bool => DB::table('auth_throttle_tuples')->insert(throttleTupleRow($parentId, [
        $column => null,
    ])))->toThrow(QueryException::class);
})->with(['window_started_at', 'tuple_digest']);
