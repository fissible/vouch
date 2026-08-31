<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Architecture;

use Fissible\Vouch\Console\RetentionManifest;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 5a — the guard that would have caught this whole task.
 *
 * `auth_token_assurances` shipped with no retention policy and nothing failed.
 * It was found by reading, months later, which is not a mechanism. This test is
 * the mechanism: every table the package owns must be DECLARED either pruned or
 * deliberately retained, and a new table that is neither fails here.
 *
 * A blanket "every auth_* table must be pruned" rule would be wrong and would be
 * disabled the first time it was inconvenient — some tables are retained on
 * purpose. `auth_enrollment_locks` is a mutex anchor whose migration explains
 * that its rows are claimed and never deleted; reaping them would be a bug, not
 * hygiene. So the manifest records the REASON, and the assertion is that no
 * table is undeclared.
 *
 * KNOWN BOUND, stated rather than papered over: this guard proves a table is
 * DECLARED, not that a table declared `pruned()` actually has a working
 * reclaimer. A future table could be added to `pruned()` and pass here on the
 * declaration alone. Closing that generically would mean re-implementing the
 * sweep inside the test or asserting on implementation structure, so the
 * behavioural proof lives with each reclaimer instead — for the two tables this
 * task adds, in TokenAssuranceSweepTest and PruneReclaimsTokenAssurancesTest.
 * The guard's job is to make an undeclared table impossible to ship silently,
 * which is the failure that actually happened.
 */
final class RetentionManifestTest extends TestCase
{
    use DatabaseMigrations;

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    /**
     * Tables THIS PACKAGE creates, derived by running its migrations and
     * observing the effect.
     *
     * Deliberately not "every table named auth_*", and deliberately not a regex
     * over the migration sources. A naming convention is not ownership: a Vouch
     * table under another prefix would be invisible to the guard and ship
     * undeclared, which is the exact failure this test exists to prevent. And
     * parsing the sources misses every form the pattern did not anticipate —
     * dynamic names, double-quoted calls, nontrivial raw DDL — which fails
     * silently, in the direction of finding too few.
     *
     * Running the migrations against an empty schema and diffing cannot miss a
     * table, because the table's existence is the observation.
     *
     * @return list<string>
     */
    private function packageTables(): array
    {
        $path = tempnam(sys_get_temp_dir(), 'vouch-manifest-') ?: sys_get_temp_dir() . '/vouch-manifest.sqlite';
        file_put_contents($path, '');

        config(['database.connections.manifest_probe' => [
            'driver' => 'sqlite',
            'database' => $path,
            'prefix' => '',
            'foreign_key_constraints' => true,
        ]]);
        DB::purge('manifest_probe');

        try {
            $schema = DB::connection('manifest_probe')->getSchemaBuilder();
            $before = $schema->getTableListing(schemaQualified: false);

            Artisan::call('migrate', [
                '--database' => 'manifest_probe',
                '--path' => realpath(__DIR__ . '/../../database/migrations'),
                '--realpath' => true,
                '--force' => true,
            ]);

            $after = $schema->getTableListing(schemaQualified: false);
        } finally {
            DB::purge('manifest_probe');
            @unlink($path);
        }

        // `migrations` is Laravel's own ledger, created by running them at all.
        $tables = array_values(array_diff($after, $before, ['migrations']));
        sort($tables);

        return $tables;
    }

    #[Test]
    public function the_derivation_finds_the_tables_this_task_is_about(): void
    {
        /*
         * A guard whose discovery step silently finds nothing passes forever.
         * Pin a few tables it must have found, including one created by raw DDL
         * rather than Schema::create.
         */
        $tables = $this->packageTables();

        self::assertContains('auth_sessions', $tables);
        self::assertContains('auth_enrollment_locks', $tables);
        self::assertContains('auth_token_assurances', $tables);
        self::assertGreaterThan(8, count($tables));
    }

    #[Test]
    public function every_package_table_is_declared_pruned_or_retained(): void
    {
        $declared = array_merge(
            array_keys(RetentionManifest::pruned()),
            array_keys(RetentionManifest::retained()),
            array_keys(RetentionManifest::unreclaimed()),
        );

        $undeclared = array_values(array_diff($this->packageTables(), $declared));

        self::assertSame([], $undeclared, sprintf(
            "These package tables declare no retention policy: %s.\n"
            . "Add each to RetentionManifest::pruned() if something reclaims it, or to "
            . "RetentionManifest::retained() with the reason it is kept. A table that is "
            . "neither is how auth_token_assurances shipped as unbounded authentication "
            . "history that nothing reclaimed.",
            implode(', ', $undeclared),
        ));
    }

    #[Test]
    public function the_manifest_declares_no_table_that_does_not_exist(): void
    {
        /*
         * The mirror failure: a manifest that drifts ahead of the schema stops
         * being evidence. A renamed or dropped table left declared makes the
         * test above pass for a table nobody has.
         */
        $tables = $this->packageTables();
        $declared = array_merge(
            array_keys(RetentionManifest::pruned()),
            array_keys(RetentionManifest::retained()),
            array_keys(RetentionManifest::unreclaimed()),
        );

        self::assertSame([], array_values(array_diff($declared, $tables)));
    }

    #[Test]
    public function no_table_is_declared_in_two_categories(): void
    {
        $pruned = array_keys(RetentionManifest::pruned());
        $retained = array_keys(RetentionManifest::retained());
        $unreclaimed = array_keys(RetentionManifest::unreclaimed());

        self::assertSame([], array_values(array_intersect($pruned, $retained)));
        self::assertSame([], array_values(array_intersect($pruned, $unreclaimed)));
        self::assertSame([], array_values(array_intersect($retained, $unreclaimed)));
    }

    #[Test]
    public function every_unreclaimed_table_names_a_tracking_issue(): void
    {
        /*
         * The category that keeps the guard honest.
         *
         * Without it, the only way to make this suite pass is to move an
         * unbounded table into retained() with a reason like "no reclaimer
         * owns its lifecycle yet" — which is the defect restated as a
         * justification, and it makes the guard certify the exact condition it
         * was built to surface. Six tables were in that position when this
         * manifest was first written.
         *
         * A declared gap is legitimate. A declared gap with nowhere to read
         * about it is just a quieter version of the original problem, so each
         * one must name the issue tracking it.
         */
        foreach (RetentionManifest::unreclaimed() as $table => $reason) {
            self::assertMatchesRegularExpression(
                '/#\d+/',
                $reason,
                sprintf('Table "%s" is declared unreclaimed without naming a tracking issue.', $table),
            );
        }
    }

    #[Test]
    public function no_retained_reason_is_really_an_admission_of_no_reclaimer(): void
    {
        /*
         * The specific laundering this guard has already caught once: a table
         * with no reclaimer placed in retained() and described as such. If that
         * is the situation, it belongs in unreclaimed() with an issue.
         */
        foreach (RetentionManifest::retained() as $table => $reason) {
            self::assertDoesNotMatchRegularExpression(
                '/no (package )?reclaimer|not reclaimed|nothing reclaims|yet\b/i',
                $reason,
                sprintf(
                    'Table "%s" is declared retained, but its reason describes a missing reclaimer. '
                    . 'Move it to unreclaimed() with a tracking issue instead.',
                    $table,
                ),
            );
        }
    }

    #[Test]
    public function every_retained_table_states_why(): void
    {
        /*
         * "Retained" without a reason is just an allow-list, and an allow-list
         * with no rationale is where the next unbounded table will be added to
         * make this test pass.
         */
        foreach (RetentionManifest::retained() as $table => $reason) {
            self::assertNotSame('', trim($reason), sprintf('Table "%s" is retained with no reason.', $table));
            self::assertGreaterThan(20, strlen(trim($reason)), sprintf(
                'Table "%s" is retained with a reason too short to be one: "%s".',
                $table,
                $reason,
            ));
        }
    }

    #[Test]
    public function token_assurances_are_declared_pruned(): void
    {
        /*
         * The specific regression. Pinned by name because this table is the
         * reason the manifest exists, and because a future refactor that drops
         * the sweep would otherwise only fail the sweep's own tests, which
         * would be deleted alongside it.
         */
        self::assertArrayHasKey('auth_token_assurances', RetentionManifest::pruned());
        self::assertArrayHasKey('auth_token_credentials', RetentionManifest::pruned());
    }
}
