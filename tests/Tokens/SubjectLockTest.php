<?php

declare(strict_types=1);

namespace Fissible\Vouch\Tests\Tokens;

use Fissible\Vouch\Tests\TestCase;
use Fissible\Vouch\Tokens\CredentialLockManager;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\VouchServiceProvider;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\Test;

/**
 * 2.4 Task 5a — the subject lock's ANCHOR, which is what makes it durable.
 *
 * The shipped lock takes `auth_sessions where user_id = ?` and calls `->first()`.
 * Two defects follow from that, and both are invisible while the only caller is
 * issuance, where a session row is guaranteed to exist:
 *
 *   - `SubjectKey::$provider` is ignored, so the lock is keyed on half an
 *     identity;
 *   - `->first()` over an empty result acquires NO LOCK AT ALL, silently. The
 *     caller believes it is serialized and is not.
 *
 * A subject-wide sweep is precisely the caller for whom "the subject may have no
 * session" is the normal case, so 5a gives the subject an anchor that always
 * exists before it is locked — following `auth_enrollment_locks`, whose
 * migration already documents why a mutex anchor carries no id, no timestamps
 * and no foreign key.
 *
 * These tests assert the anchor's OBSERVABLE properties. Whether two
 * transactions genuinely exclude each other is a claim about a database, not
 * about PHP, and is proven against real engines in
 * tests/Concurrency/SubjectLockContentionTest.php instead.
 */
final class SubjectLockTest extends TestCase
{
    use DatabaseMigrations;

    /** @return array<int, class-string> */
    protected function getPackageProviders($app): array
    {
        return [VouchServiceProvider::class];
    }

    private function locks(): CredentialLockManager
    {
        return app(CredentialLockManager::class);
    }

    #[Test]
    public function it_serializes_a_subject_that_has_no_session_row(): void
    {
        /*
         * The defect that motivates the whole task. Under the shipped lock this
         * subject has nothing to lock, `->first()` returns null, and acquire()
         * returns successfully having serialized nothing — the failure mode is
         * silence, not an error.
         *
         * Asserted as the anchor existing afterwards, because "a lock was held"
         * is not observable from inside the transaction that holds it.
         */
        self::assertSame(0, DB::table('auth_sessions')->count());

        DB::transaction(function (): void {
            $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\User', '7'), []);
        });

        self::assertSame(1, DB::table('auth_subject_locks')->count());
        self::assertSame(
            'App\\Models\\User:7',
            DB::table('auth_subject_locks')->value('subject_key'),
        );
    }

    #[Test]
    public function it_keys_the_anchor_by_provider_and_id_together(): void
    {
        /*
         * Same id, two providers. A lock keyed on `user_id` alone gives these
         * one anchor, which is wrong in both directions at once: it makes two
         * unrelated subjects contend, and it lets a lock taken for one provider
         * be mistaken for exclusion of the other.
         *
         * The separator is the FINAL colon, and ids may not contain one, so a
         * namespaced provider stays unambiguous.
         */
        DB::transaction(function (): void {
            $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\User', '7'), []);
            $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\Admin', '7'), []);
        });

        $keys = DB::table('auth_subject_locks')->orderBy('subject_key')->pluck('subject_key')->all();

        self::assertSame(['App\\Models\\Admin:7', 'App\\Models\\User:7'], $keys);
    }

    #[Test]
    public function it_does_not_confuse_subject_ids_that_differ_only_as_strings(): void
    {
        /*
         * `SubjectKey` keeps ids as strings for exactly this reason: numeric
         * coercion would let '07' answer for '7', attaching one subject's
         * assurance to another. The anchor must preserve that distinction, so
         * the column cannot be an integer and the comparison cannot be numeric.
         */
        DB::transaction(function (): void {
            $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\User', '7'), []);
            $this->locks()->acquire(DB::connection(), SubjectKey::of('App\\Models\\User', '07'), []);
        });

        self::assertSame(2, DB::table('auth_subject_locks')->count());
    }

    #[Test]
    public function it_claims_the_anchor_once_and_reuses_it(): void
    {
        /*
         * The anchor is a mutex, not a record: claimed with insertOrIgnore,
         * never deleted, carrying no state beyond its existence. A second
         * acquisition must find the same row rather than accumulate rows or
         * fail on the unique index.
         */
        $subject = SubjectKey::of('App\\Models\\User', '7');

        DB::transaction(fn () => $this->locks()->acquire(DB::connection(), $subject, []));
        DB::transaction(fn () => $this->locks()->acquire(DB::connection(), $subject, []));
        DB::transaction(fn () => $this->locks()->acquire(DB::connection(), $subject, []));

        self::assertSame(1, DB::table('auth_subject_locks')->count());
    }

    #[Test]
    public function it_locks_the_subject_before_any_credential(): void
    {
        /*
         * Lock ORDER is the deadlock protocol, not an implementation detail:
         * subject first, then credentials in canonical order. Two callers that
         * disagree about the order deadlock, and a deadlock under a subject-wide
         * sweep is a stuck maintenance job holding a subject hostage.
         */
        /** @var list<string> $order */
        $order = [];
        $manager = new class($order) extends CredentialLockManager {
            /** @param list<string> $order */
            public function __construct(public array &$order) {}

            protected function lockSubject(SubjectKey $subject): void
            {
                $this->order[] = 'subject:' . $subject->toString();
            }

            protected function lockCredential(string $credentialId): void
            {
                $this->order[] = 'credential:' . $credentialId;
            }
        };

        $manager->acquire(
            DB::connection(),
            SubjectKey::of('App\\Models\\User', '7'),
            ['9', '09', '10'],
        );

        self::assertSame(
            ['subject:App\\Models\\User:7', 'credential:09', 'credential:10', 'credential:9'],
            $order,
        );
    }

    #[Test]
    public function the_anchor_is_a_mutex_not_a_record(): void
    {
        /*
         * `auth_enrollment_locks` documents the shape and the reasons: no id,
         * no timestamps, and deliberately NO foreign key, because a mutex
         * anchor must not cascade-delete with the user and must not couple the
         * hottest statement in the protocol to a lookup on the host's users
         * table. The same reasoning applies here and the shape must match, or
         * the anchor acquires a lifecycle it is not allowed to have.
         */
        $schema = DB::connection()->getSchemaBuilder();
        $columns = $schema->getColumnListing('auth_subject_locks');
        sort($columns);

        self::assertSame(['subject_key'], $columns);

        /*
         * And no foreign key. auth_enrollment_locks is explicit about why: a
         * mutex anchor must not cascade-delete with the user, and constraining
         * it would couple the most contended statement in the protocol to a
         * lookup on the host's users table for a row that references nothing
         * and outlives nothing.
         */
        self::assertSame([], $schema->getForeignKeys('auth_subject_locks'));
    }

    #[Test]
    public function the_anchor_is_never_reclaimed_by_maintenance(): void
    {
        /*
         * The anchor is claimed and never deleted. A retention policy that
         * reaped it would delete the serialization row out from under a
         * concurrent holder, and — because ensure-then-lock re-creates it — the
         * damage would show up as two callers both proceeding, not as an error.
         *
         * Task 5a adds a retention manifest; this pins which side of it the
         * anchor belongs on, behaviourally rather than by declaration.
         */
        $subject = SubjectKey::of('App\Models\User', '7');
        DB::transaction(fn () => $this->locks()->acquire(DB::connection(), $subject, []));

        Artisan::call('vouch:prune');

        self::assertSame(1, DB::table('auth_subject_locks')->count());
    }

    #[Test]
    public function the_anchor_survives_the_subject_losing_every_session(): void
    {
        /*
         * The anchor must not be coupled to session lifetime, or the sweep loses
         * its serialization exactly when a subject is fully logged out — which
         * is the state a subject-wide revocation is most likely to run against.
         */
        $subject = SubjectKey::of('App\\Models\\User', '7');
        DB::transaction(fn () => $this->locks()->acquire(DB::connection(), $subject, []));

        DB::table('auth_sessions')->delete();

        self::assertSame(1, DB::table('auth_subject_locks')->count());
    }
}
