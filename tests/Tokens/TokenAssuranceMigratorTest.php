<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 2 — the upgrade on a real migrator.
 *
 * DELIBERATELY WITHOUT DatabaseMigrations. That trait migrates and rolls back
 * around every test, so the replacement has already run and been RECORDED
 * before the body starts — which means calling `$migration->up()` by hand
 * proves the migration's schema effect but not the thing an installed host
 * actually does: "old migration recorded, replacement pending, migrator runs
 * it". It also bypasses the repository, so a replacement that is never
 * recorded would re-run on the next deploy and fail on an already-renamed
 * table.
 *
 * Same harness as SessionAssuranceUpgradeTest, for the same reason.
 */
final class TokenAssuranceMigratorTest extends TestCase
{
    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    private static function migrationsDirectory(): string
    {
        $dir = realpath(__DIR__ . '/../../database/migrations');

        if ($dir === false) {
            throw new \RuntimeException('The migrations directory does not exist.');
        }

        return $dir;
    }

    private static function replacementFile(): string
    {
        $matches = glob(self::migrationsDirectory() . '/*token_assurance_identity*.php');
        $matches = $matches === false ? [] : $matches;

        self::assertCount(1, $matches, 'The replacement must ship as exactly one new migration.');

        return $matches[0];
    }

    /** Stage every migration EXCEPT the replacement, so the migrator can build the old shape. */
    private static function stagedDirectory(): string
    {
        $staged = sys_get_temp_dir() . '/vouch-pre-t2-' . getmypid();

        if (! is_dir($staged)) {
            mkdir($staged, 0777, true);
        }

        $files = glob(self::migrationsDirectory() . '/*.php');

        foreach ($files === false ? [] : $files as $file) {
            if ($file !== self::replacementFile()) {
                copy($file, $staged . '/' . basename($file));
            }
        }

        return $staged;
    }

    protected function tearDown(): void
    {
        $staged = sys_get_temp_dir() . '/vouch-pre-t2-' . getmypid();
        $files = glob($staged . '/*.php');

        foreach ($files === false ? [] : $files as $file) {
            unlink($file);
        }

        if (is_dir($staged)) {
            rmdir($staged);
        }

        Artisan::call('migrate:fresh');

        parent::tearDown();
    }

    #[Test]
    public function the_migrator_runs_the_replacement_over_an_installed_old_shape(): void
    {
        Artisan::call('migrate:fresh', ['--path' => self::stagedDirectory(), '--realpath' => true]);

        // Guards the harness: if staging silently included the replacement, every
        // assertion below would pass for the wrong reason.
        self::assertTrue(Schema::hasColumn('auth_token_assurances', 'token_id'));
        self::assertFalse(Schema::hasTable('auth_token_credentials'));

        DB::table('auth_token_assurances')->insert([
            'token_id' => 42,
            'acr' => 'aal2',
            'amr' => json_encode(['password', 'totp']),
            'credential_ids' => json_encode([9]),
            'issuing_session_id' => 'sess-1',
            'issued_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        Artisan::call('migrate', ['--path' => self::replacementFile(), '--realpath' => true]);

        self::assertFalse(Schema::hasColumn('auth_token_assurances', 'token_id'));
        self::assertTrue(Schema::hasColumn('auth_token_assurances', 'issuer_key'));
        self::assertTrue(Schema::hasTable('auth_token_credentials'));

        // §6.5 point 4: nothing is adopted. The old row is discarded rather than
        // half-migrated into a shape whose proof column nobody ever wrote.
        self::assertSame(0, DB::table('auth_token_assurances')->count());
    }

    #[Test]
    public function the_replacement_is_recorded_and_does_not_run_twice(): void
    {
        /*
         * The repository half, which calling up() by hand cannot show. An
         * unrecorded migration re-runs on the next deploy and fails against a
         * table it has already replaced — turning a successful upgrade into a
         * broken second deploy.
         */
        Artisan::call('migrate:fresh', ['--path' => self::stagedDirectory(), '--realpath' => true]);
        Artisan::call('migrate', ['--path' => self::replacementFile(), '--realpath' => true]);

        $exitCode = Artisan::call('migrate', ['--path' => self::replacementFile(), '--realpath' => true]);

        self::assertSame(0, $exitCode);
        self::assertTrue(Schema::hasColumn('auth_token_assurances', 'issuer_key'));
    }
}
