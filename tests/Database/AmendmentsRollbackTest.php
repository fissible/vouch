<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schema;

/*
 * Step 9 verification, adapted.
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
it('rolls back and re-applies the four amendment migrations cleanly', function (): void {
    Artisan::call('migrate:fresh');

    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeTrue()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeTrue()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeTrue();

    expect(Artisan::call('migrate:rollback', ['--step' => 4]))->toBe(0);

    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeFalse()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeFalse()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeFalse()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeFalse();

    expect(Artisan::call('migrate'))->toBe(0);

    expect(Schema::hasColumn('auth_credentials', 'identifier_id'))->toBeTrue()
        ->and(Schema::hasColumn('auth_credentials', 'last_used_timestep'))->toBeTrue()
        ->and(Schema::hasColumn('auth_challenges', 'credential_id'))->toBeTrue()
        ->and(Schema::hasTable('auth_enrollment_locks'))->toBeTrue();
});
