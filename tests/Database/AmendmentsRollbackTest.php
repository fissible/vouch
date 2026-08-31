<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;

/*
 * Amendment migration verification, adapted.
 *
 * The brief's plain `vendor/bin/testbench migrate:fresh|migrate:rollback|migrate`
 * commands boot Testbench's own skeleton application, which never registers
 * VouchServiceProvider and therefore never calls loadMigrationsFrom() for this
 * package (there is no testbench.yaml/workbench wiring it in) -- those commands
 * only touch Testbench's own users/cache/jobs migrations and see none of the
 * four amendment files. Running the same fresh -> rollback -> re-migrate cycle
 * through Artisan inside this package's own TestCase (which DOES register
 * VouchServiceProvider, exactly as the real Pest suite does) exercises the
 * same down()/up() pairs Testbench would have, against the same driver.
 */
it('rolls back and re-applies every migration cleanly', function (): void {
    /*
     * ROLLS BACK EVERYTHING, deliberately, rather than a literal --step count.
     *
     * This read `--step => 12` and was coupled to the total number of
     * migrations in the package: 2.4 Task 2 added one, which shifted the window
     * so the rollback removed a different set than the assertions below
     * describe, and the re-migrate did not restore what it had taken. The
     * damage was not confined to this test — the process kept running against a
     * half-rolled-back schema, so six unrelated suites failed with missing
     * columns they never touch.
     *
     * A full reset has no count to drift, and exercises every down() rather
     * than the most recent twelve — which is what this file is for.
     */
    Artisan::call('migrate:fresh');

    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeTrue()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeTrue()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_counters'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_locks'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_ip_windows'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_tuples'))->toBeTrue()
        ->and(Schema::hasTable('auth_delivery_spend'))->toBeTrue()
        ->and(Schema::hasTable('auth_delivery_spend_reservations'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'is_decoy'))->toBeTrue()
        ->and(Schema::hasTable('auth_challenge_outbox'))->toBeTrue();

    expect(Artisan::call('migrate:reset'))->toBe(0);

    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeFalse()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeFalse()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeFalse()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeFalse()
        ->and(Schema::hasTable('auth_throttle_counters'))->toBeFalse()
        ->and(Schema::hasTable('auth_throttle_locks'))->toBeFalse()
        ->and(Schema::hasTable('auth_throttle_ip_windows'))->toBeFalse()
        ->and(Schema::hasTable('auth_throttle_tuples'))->toBeFalse()
        ->and(Schema::hasTable('auth_delivery_spend'))->toBeFalse()
        ->and(Schema::hasTable('auth_delivery_spend_reservations'))->toBeFalse()
        ->and(Schema::hasColumn('auth_challenges', 'is_decoy'))->toBeFalse()
        ->and(Schema::hasTable('auth_challenge_outbox'))->toBeFalse();

    expect(Artisan::call('migrate'))->toBe(0);

    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeTrue()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeTrue()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_counters'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_locks'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_ip_windows'))->toBeTrue()
        ->and(Schema::hasTable('auth_throttle_tuples'))->toBeTrue()
        ->and(Schema::hasTable('auth_delivery_spend'))->toBeTrue()
        ->and(Schema::hasTable('auth_delivery_spend_reservations'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'is_decoy'))->toBeTrue()
        ->and(Schema::hasTable('auth_challenge_outbox'))->toBeTrue();
});
