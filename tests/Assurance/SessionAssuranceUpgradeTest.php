<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/*
 * 2.4 Task 2a — the forward upgrade, on a real migrator.
 *
 * DELIBERATELY WITHOUT RefreshDatabase. This exercises schema changes, and the
 * transactional isolation that trait provides is actively wrong here: MySQL
 * commits DDL implicitly, so a migration run inside the wrapping transaction
 * ends it half way through and every later assertion reads uncommitted-then-
 * committed state. It also bypasses the migration repository, so nothing about
 * a host's actual `php artisan migrate` is being tested.
 *
 * Instead: migrate to the 0.1.1 shape using every migration EXCEPT this task's,
 * insert the rows a real host would already have, then run the migrator forward
 * one step and inspect what survived.
 */

function migrationsDirectory(): string
{
    return (string) realpath(__DIR__ . '/../../database/migrations');
}

function upgradeMigrationFile(): string
{
    $matches = glob(migrationsDirectory() . '/*_session_assurance_proof*.php');

    expect($matches)->toBeArray()->toHaveCount(1);

    return $matches[0];
}

/**
 * Stage every migration except this task's into a temporary directory, so the
 * migrator can build the pre-upgrade schema without the file under test.
 */
function stagePreUpgradeMigrations(): string
{
    $staged = sys_get_temp_dir() . '/vouch-pre-2a-' . getmypid();

    if (! is_dir($staged)) {
        mkdir($staged, 0777, true);
    }

    foreach ((array) glob(migrationsDirectory() . '/*.php') as $file) {
        if ($file !== upgradeMigrationFile()) {
            copy($file, $staged . '/' . basename($file));
        }
    }

    return $staged;
}

function migrateToPreUpgrade(): void
{
    Artisan::call('migrate:fresh', ['--path' => stagePreUpgradeMigrations(), '--realpath' => true]);
}

function migrateForwardOneStep(): void
{
    Artisan::call('migrate', ['--path' => upgradeMigrationFile(), '--realpath' => true]);
}

afterEach(function (): void {
    // Leave the database in the fully-migrated shape every other suite expects.
    Artisan::call('migrate:fresh');

    $staged = sys_get_temp_dir() . '/vouch-pre-2a-' . getmypid();
    foreach ((array) glob($staged . '/*.php') as $file) {
        unlink($file);
    }
    if (is_dir($staged)) {
        rmdir($staged);
    }
});

it('builds the 0.1.1 shape before the upgrade runs', function (): void {
    // Guards the harness itself. If staging silently included the new
    // migration, every assertion below would pass for the wrong reason.
    migrateToPreUpgrade();

    expect(Schema::hasColumn('auth_sessions', 'last_factor_at'))->toBeTrue()
        ->and(Schema::hasColumn('auth_sessions', 'assurance_facts'))->toBeTrue()
        ->and(Schema::hasColumn('auth_sessions', 'assurance_proof'))->toBeFalse();
});

it('carries an existing session across the upgrade', function (): void {
    migrateToPreUpgrade();

    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('f', 64),
        'user_id' => 11,
        'amr' => json_encode(['password', 'totp']),
        'acr' => 'aal2',
        'assurance_facts' => json_encode(['multi_factor' => true]),
        'last_factor_at' => '2026-07-01 10:00:00',
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    migrateForwardOneStep();

    $row = DB::table('auth_sessions')->where('user_id', 11)->first();

    expect($row)->not->toBeNull()
        ->and($row->session_binding)->toBe(str_repeat('f', 64))
        ->and($row->acr)->toBe('aal2')
        // No proof is invented for it. The row survives; its authority does not.
        ->and($row->assurance_proof)->toBeNull();
});

it('carries the recency value across the rename rather than resetting it', function (): void {
    /*
     * A rename implemented as "add the new column, drop the old one" looks
     * identical in a schema check and silently nulls every existing session's
     * recency anchor. On a max_age requirement that treats a null anchor as
     * "nothing recorded", that is a fail-open for the entire installed base.
     */
    migrateToPreUpgrade();

    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('g', 64),
        'user_id' => 12,
        'amr' => json_encode(['password']),
        'acr' => 'aal1',
        'last_factor_at' => '2026-06-15 08:30:00',
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    migrateForwardOneStep();

    expect(substr(stringValue(DB::table('auth_sessions')->where('user_id', 12)->value('weakest_satisfied_at')), 0, 19))
        ->toBe('2026-06-15 08:30:00');
});

it('discards the derived summary column, and says so', function (): void {
    /*
     * INTENTIONAL DATA LOSS, asserted rather than left implicit. Nothing in
     * Vouch ever wrote assurance_facts, so within Vouch the loss is a
     * non-event -- but a host cannot be proven not to have written it, so the
     * upgrade notes must state that this column is dropped and its contents are
     * not migrated. There is nowhere honest to migrate them TO: a derived
     * summary is not a proof, and reconstructing factors from it would assert
     * facts nobody witnessed.
     */
    migrateToPreUpgrade();

    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('h', 64),
        'user_id' => 13,
        'amr' => json_encode(['password']),
        'acr' => 'aal1',
        'assurance_facts' => json_encode(['host_wrote_this' => true]),
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    migrateForwardOneStep();

    expect(Schema::hasColumn('auth_sessions', 'assurance_facts'))->toBeFalse()
        ->and(DB::table('auth_sessions')->where('user_id', 13)->exists())->toBeTrue();
});

it('keeps the unique binding constraint through the upgrade', function (): void {
    /*
     * SQLite renames a column by rebuilding the table. A rebuild that omits an
     * index is invisible to every column check and permits two live sessions
     * per binding -- the inverse of what the original migration went out of its
     * way to guarantee.
     */
    migrateToPreUpgrade();
    migrateForwardOneStep();

    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('i', 64),
        'user_id' => 14,
        'amr' => json_encode(['password']),
        'acr' => 'aal1',
        'created_at' => now(),
        'updated_at' => now(),
    ]);

    expect(fn () => DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('i', 64),
        'user_id' => 15,
        'amr' => json_encode(['password']),
        'acr' => 'aal1',
        'created_at' => now(),
        'updated_at' => now(),
    ]))->toThrow(Illuminate\Database\QueryException::class);
});

it('runs forward exactly once and stays applied', function (): void {
    // A migration that is not recorded in the repository re-runs on the next
    // deploy, and a rename that runs twice fails the whole deploy.
    migrateToPreUpgrade();
    migrateForwardOneStep();
    migrateForwardOneStep();

    expect(Schema::hasColumn('auth_sessions', 'weakest_satisfied_at'))->toBeTrue()
        ->and(Schema::hasColumn('auth_sessions', 'last_factor_at'))->toBeFalse();
});
