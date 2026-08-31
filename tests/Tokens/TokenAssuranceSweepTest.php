<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use DateTimeImmutable;
use Fissible\Vouch\Contracts\ReportsTokenExistence;
use Fissible\Vouch\Contracts\TokenIssuer;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Tests\Support\Tokens\ExistenceReportingIssuer;
use Fissible\Vouch\Tests\Support\Tokens\SilentIssuer;
use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenAssuranceSweep;
use Fissible\Vouch\Tokens\TokenAssuranceSweepResult;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Database\Events\TransactionCommitted;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 5a — reclaiming orphaned token-assurance records (addendum §3c).
 *
 * `auth_token_assurances` describes how a person authenticated: factor ids,
 * credential ids, timestamps, subject. That is MORE sensitive than the Sanctum
 * row it annotates, which is an id and a hash. Nothing reclaims it today, and
 * both `sanctum:prune-expired` and `$user->tokens()->delete()` hard-delete
 * tokens without telling Vouch.
 *
 * Every test here exists because the obvious implementation is dangerous in a
 * specific way. The sweep deletes authentication records; the failure mode of
 * getting it wrong is not a stale row but a live token that fails closed at a
 * default-deny gate with nothing to diagnose it by.
 */
final class TokenAssuranceSweepTest extends TestCase
{
    use DatabaseMigrations;

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    /** @return list<SatisfiedFactor> */
    private function proof(string $satisfiedAt = '2026-08-13T10:00:00+00:00'): array
    {
        return [new SatisfiedFactor(
            'password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
            false, false, false, null, new DateTimeImmutable($satisfiedAt),
        )];
    }

    private function record(string $issuerKey, string $tokenKey, string $satisfiedAt = '2026-08-13T10:00:00+00:00'): void
    {
        app(TokenAssuranceRecord::class)->store(
            $issuerKey,
            $tokenKey,
            SubjectKey::of('App\\Models\\User', '7'),
            null,
            ActorKind::Human,
            $this->proof($satisfiedAt),
        );
    }

    /** @param array<string, TokenIssuer> $issuers */
    private function sweepWith(array $issuers, int $batch = 100): TokenAssuranceSweepResult
    {
        // The registry is readonly and constructor-injected, so the double is
        // installed as an instance rather than mutated into place.
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry(array_values($issuers)));

        return app()->makeWith(TokenAssuranceSweep::class, ['batchSize' => $batch])->sweep();
    }

    /** @return list<string> */
    private function remainingKeys(): array
    {
        $keys = DB::table('auth_token_assurances')->orderBy('token_key')->pluck('token_key')->all();

        return array_values(array_map(stringValue(...), $keys));
    }

    #[Test]
    public function a_live_long_lived_token_survives_however_old_its_evidence_is(): void
    {
        /*
         * The single most important test in this file, and the one that fails
         * if anyone implements the obvious version.
         *
         * `weakest_satisfied_at` is EVIDENCE age, not token age. A legitimately
         * long-lived API token has an ancient anchor by design. Pruning on it
         * deletes the record for a token that still exists, after which §2's
         * default-deny gate refuses that token with `invalid_token` — the same
         * bytes it renders for a token that was never recorded at all. There is
         * nothing in the response, the logs, or the database to distinguish
         * "your record was reaped" from "you minted this outside Vouch".
         */
        $this->record('sanctum', 'ancient-but-live', '2019-01-01T00:00:00+00:00');

        $result = $this->sweepWith(['sanctum' => new ExistenceReportingIssuer('sanctum', ['ancient-but-live'])]);

        self::assertSame(['ancient-but-live'], $this->remainingKeys());
        self::assertSame(0, $result->reclaimed);
        self::assertSame(1, $result->retained);
    }

    #[Test]
    public function it_reclaims_only_records_the_issuer_reports_absent(): void
    {
        $this->record('sanctum', 'still-here');
        $this->record('sanctum', 'gone');

        $result = $this->sweepWith(['sanctum' => new ExistenceReportingIssuer('sanctum', ['still-here'])]);

        self::assertSame(['still-here'], $this->remainingKeys());
        self::assertSame(1, $result->reclaimed);
        self::assertSame(1, $result->retained);
    }

    #[Test]
    public function an_issuer_without_the_capability_is_skipped_and_reported(): void
    {
        /*
         * Absence of the capability is not evidence of absence of a token. This
         * is why existence is an optional contract rather than a TokenIssuer
         * method: forced to answer, an issuer that cannot would return the
         * cheapest thing that compiles — an empty array — which reads as "every
         * token I own is gone" and deletes all of them.
         *
         * Skipped is not the same as silent: the count is reported so an
         * operator can see that a table is growing because nothing can sweep it.
         */
        $this->record('legacy', 'unanswerable');

        $result = $this->sweepWith(['legacy' => new SilentIssuer('legacy')]);

        self::assertSame(['unanswerable'], $this->remainingKeys());
        self::assertSame(0, $result->reclaimed);
        self::assertSame(1, $result->unsupported);
    }

    #[Test]
    public function records_of_an_unregistered_issuer_are_never_reclaimed(): void
    {
        /*
         * A host that removes an issuer from configuration has not thereby
         * revoked its tokens. If an unregistered issuer's records were swept,
         * deleting one line of config would silently invalidate every token it
         * ever issued the next time maintenance ran.
         */
        $this->record('departed', 'orphaned-by-config');

        $result = $this->sweepWith(['sanctum' => new ExistenceReportingIssuer('sanctum', [])]);

        self::assertSame(['orphaned-by-config'], $this->remainingKeys());
        self::assertSame(0, $result->reclaimed);
        self::assertSame(1, $result->unsupported);
    }

    #[Test]
    public function a_capability_error_retains_the_records_and_is_reported(): void
    {
        /*
         * A sweep that cannot ask must not delete. The failure direction matters
         * more than the failure: retaining a record costs storage, deleting a
         * live one costs a working token.
         */
        $this->record('sanctum', 'a');
        $this->record('sanctum', 'b');

        $result = $this->sweepWith([
            'sanctum' => new ExistenceReportingIssuer('sanctum', [], throws: new \RuntimeException('driver unreachable')),
        ]);

        self::assertSame(['a', 'b'], $this->remainingKeys());
        self::assertSame(0, $result->reclaimed);
        self::assertSame(1, $result->errored);
        self::assertStringContainsString('sanctum', $result->errors[0]);
        self::assertStringContainsString('driver unreachable', $result->errors[0]);
    }

    #[Test]
    public function one_issuers_failure_does_not_stop_another_issuers_sweep(): void
    {
        /*
         * Maintenance over N issuers must not be all-or-nothing, or a single
         * unreachable driver freezes retention for every other one.
         */
        $this->record('broken', 'kept-by-error');
        $this->record('sanctum', 'gone');

        $result = $this->sweepWith([
            'broken' => new ExistenceReportingIssuer('broken', [], throws: new \RuntimeException('down')),
            'sanctum' => new ExistenceReportingIssuer('sanctum', []),
        ]);

        self::assertSame(['kept-by-error'], $this->remainingKeys());
        self::assertSame(1, $result->reclaimed);
        self::assertSame(1, $result->errored);
    }

    #[Test]
    public function an_issuer_cannot_vouch_for_another_issuers_token_key(): void
    {
        /*
         * Token keys are only unique WITHIN an issuer — the table's unique index
         * is (issuer_key, token_key). If the sweep matched returned keys without
         * scoping them, a compromised or merely sloppy issuer could keep another
         * issuer's records alive, or, in the mirror case, an issuer reporting a
         * key it does not own could contribute to another's reclamation.
         */
        $this->record('sanctum', 'shared-1');
        $this->record('other', 'shared-1');

        $result = $this->sweepWith([
            'sanctum' => new ExistenceReportingIssuer('sanctum', ['shared-1']),
            'other' => new ExistenceReportingIssuer('other', []),
        ]);

        $rows = DB::table('auth_token_assurances')->orderBy('issuer_key')->pluck('issuer_key')->all();

        self::assertSame(['sanctum'], $rows);
        self::assertSame(1, $result->reclaimed);
        self::assertSame(1, $result->retained);
    }

    #[Test]
    public function keys_the_issuer_was_not_asked_about_are_ignored(): void
    {
        /*
         * An issuer answering beyond its question must not widen the sweep's
         * effect. Ignoring the extra key is the conservative reading and the
         * only one that keeps the result a function of what was asked.
         */
        $this->record('sanctum', 'asked-and-gone');

        $result = $this->sweepWith([
            'sanctum' => new ExistenceReportingIssuer('sanctum', ['never-asked-about', 'nor-this']),
        ]);

        self::assertSame([], $this->remainingKeys());
        self::assertSame(1, $result->reclaimed);
        self::assertSame(0, $result->retained);
    }

    #[Test]
    public function duplicate_keys_in_the_response_are_tolerated_deterministically(): void
    {
        /*
         * A duplicate is a plausible thing for a batching issuer to return. It
         * must retain once, not count twice — otherwise the reported totals stop
         * reconciling with the table and an operator cannot tell a duplicate
         * from a genuine second record.
         */
        $this->record('sanctum', 'dupe');
        $this->record('sanctum', 'gone');

        $result = $this->sweepWith([
            'sanctum' => new ExistenceReportingIssuer('sanctum', ['dupe', 'dupe', 'dupe']),
        ]);

        self::assertSame(['dupe'], $this->remainingKeys());
        self::assertSame(1, $result->retained);
        self::assertSame(1, $result->reclaimed);
    }

    #[Test]
    public function it_asks_in_bounded_batches_rather_than_one_unbounded_query(): void
    {
        /*
         * An unbounded sweep hands the issuer every key it owns in one call. On
         * a host with a large token estate that is a query the driver may refuse
         * outright, and maintenance that fails on exactly the installations that
         * most need it is worse than maintenance that is slow.
         */
        for ($i = 0; $i < 25; $i++) {
            $this->record('sanctum', sprintf('token-%02d', $i));
        }

        $issuer = new ExistenceReportingIssuer('sanctum', []);
        $this->sweepWith(['sanctum' => $issuer], batch: 10);

        /*
         * The BOUND is the contract, not a chunk-filling strategy. Asserting
         * [10, 10, 5] would reject a perfectly correct implementation that
         * batched [8, 8, 8, 1]. What must hold: more than one request, none
         * larger than the bound, every key asked about exactly once.
         */
        $asked = array_merge(...$issuer->askedBatches);

        self::assertGreaterThan(1, count($issuer->askedBatches));
        foreach ($issuer->askedBatches as $batch) {
            self::assertLessThanOrEqual(10, count($batch));
            self::assertNotSame([], $batch);
        }
        self::assertCount(25, $asked);
        self::assertCount(25, array_unique($asked));
    }

    #[Test]
    public function it_never_asks_an_issuer_to_revoke_anything(): void
    {
        /*
         * The sweep is maintenance, not revocation. It runs against records
         * whose tokens the issuer has ALREADY said are gone, so a driver call
         * would at best be a no-op and at worst a destructive one — and it would
         * put deletion of live host state inside a scheduled job whose charter
         * is reaping dead rows.
         */
        $this->record('sanctum', 'gone');

        $issuer = new ExistenceReportingIssuer('sanctum', []);
        $this->sweepWith(['sanctum' => $issuer]);

        self::assertSame([], $issuer->revoked);
    }

    #[Test]
    public function it_refuses_to_run_inside_a_caller_transaction(): void
    {
        /*
         * Maintenance must not enlist in an authorization transaction: a sweep
         * that joined one would let a long maintenance pass hold locks taken for
         * a request, and would let a request's rollback silently undo committed
         * reclamation.
         *
         * Asserted as a REFUSAL rather than by observing the transaction level
         * afterwards. "Level is zero when I return" is also true of a sweep that
         * happily joined the caller's transaction, so it proves nothing; this is
         * the mirror of Vouch::issueToken, which requires an active transaction
         * and says so rather than coping.
         */
        $this->record('sanctum', 'gone');
        app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([
            new ExistenceReportingIssuer('sanctum', []),
        ]));
        $sweep = app()->makeWith(TokenAssuranceSweep::class, ['batchSize' => 100]);

        DB::beginTransaction();

        try {
            $this->expectException(\LogicException::class);
            $sweep->sweep();
        } finally {
            DB::rollBack();
        }
    }

    #[Test]
    public function a_record_and_its_mappings_are_reclaimed_in_one_transaction(): void
    {
        /*
         * Two separate transactions would leave credential ids -- the most
         * sensitive column of the pair -- orphaned in auth_token_credentials if
         * anything failed between them, which is the retention problem this task
         * exists to close, relocated rather than solved.
         *
         * Counted as commits rather than inspected as SQL: one reclaimed record
         * must produce exactly one commit, and a two-transaction implementation
         * produces two whatever the statements look like.
         */
        /*
         * Two distinct credentials, because an implementation that deleted only
         * the first mapping would pass with one.
         */
        app(TokenAssuranceRecord::class)->store(
            'sanctum', 'gone', SubjectKey::of('App\\Models\\User', '7'), null, ActorKind::Human,
            [
                new SatisfiedFactor('password', 'cred-1', FactorKind::Knowledge, FactorStrength::Knowledge,
                    false, false, false, null, new DateTimeImmutable('2026-08-13T10:00:00+00:00')),
                new SatisfiedFactor('totp', 'cred-2', FactorKind::Possession, FactorStrength::Possession,
                    false, false, false, null, new DateTimeImmutable('2026-08-13T10:05:00+00:00')),
            ],
        );
        self::assertSame(2, DB::table('auth_token_credentials')->count());

        $commits = 0;
        Event::listen(TransactionCommitted::class, function () use (&$commits): void {
            $commits++;
        });

        $this->sweepWith(['sanctum' => new ExistenceReportingIssuer('sanctum', [])]);

        self::assertSame(0, DB::table('auth_token_assurances')->count());
        self::assertSame(0, DB::table('auth_token_credentials')->count());
        self::assertSame(1, $commits);
    }

    #[Test]
    public function a_sweep_with_nothing_to_do_reports_zero_rather_than_failing(): void
    {
        $result = $this->sweepWith(['sanctum' => new ExistenceReportingIssuer('sanctum', [])]);

        self::assertSame(0, $result->reclaimed);
        self::assertSame(0, $result->retained);
        self::assertSame(0, $result->unsupported);
        self::assertSame(0, $result->errored);
    }
}
