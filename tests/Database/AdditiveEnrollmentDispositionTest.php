<?php

declare(strict_types=1);

use Fissible\Vouch\Credentials\CredentialCleanupStep;
use Fissible\Vouch\Factors\FactorRegistry;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\SelfService\SelfServiceOutcome;
use Fissible\Vouch\SelfService\SelfServiceResult;
use Fissible\Vouch\SelfService\WriteDisposition;
use Fissible\Vouch\Tests\Support\InterceptingFactor;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\Events\TransactionCommitting;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Hash;

/*
 * #84. What addFactor()'s ADDITIVE branch says when it fails after committing.
 *
 * A host listener on a credential event can run afterCommit -- Laravel queues
 * jobs that way by default -- and throw with the credential already durable.
 * That branch used to answer Refused, which callers read as "nothing was
 * written". The decision recorded on #84:
 *
 *   - a seventh outcome, StateMayHaveChanged, so the careless reading of
 *     $result->outcome is the safe one;
 *   - a write disposition on the result -- Committed, NotCommitted or
 *     Indeterminate -- because an empty driverFailures list proves neither;
 *   - Refused keeps meaning no credential write committed;
 *   - CredentialChangeFailed stays off this path, since it implies a
 *     revocation the additive branch never performs.
 *
 * Two choices the issue left open, pinned here: a Committed failure hands
 * over the enrollment's secrets, because the credential exists; and a FAILED
 * Indeterminate withholds them, because it may not. A nested SUCCESS is also
 * Indeterminate, since the caller's commit decides, and keeps its secrets.
 *
 * DatabaseMigrations because the claims are about COMMITS. A RefreshDatabase
 * wrapper would make every write nested in the test's own transaction.
 */
uses(DatabaseMigrations::class);

const DISPOSITION_SENTINEL = 'disposition-sentinel-8f3a: a host listener failed after commit';

function dispositionUser(int $userId = 1): void
{
    AuthIdentifier::create([
        'user_id' => $userId,
        'type' => 'email',
        'value' => "user{$userId}@acme.example",
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)
        ->enroll($userId, ['password' => 'old-password']);
}

function dispositionSession(int $userId = 1, string $binding = 'disposition-1'): AuthSession
{
    return AuthSession::create([
        'user_id' => $userId,
        'session_binding' => str_pad($binding, 64, 'a'),
        'amr' => ['pwd', 'otp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProof($userId, 'aal2'),
        'weakest_satisfied_at' => now(),
    ]);
}

function dispositionAddTotp(AuthSession $session): SelfServiceResult
{
    return app(CredentialSelfService::class)->addFactor($session, 'totp', ['label' => 'phone']);
}

function dispositionActiveTotps(int $userId = 1): int
{
    // A fresh query on the default connection, outside any transaction the
    // service opened, so only committed rows can be counted.
    return AuthCredential::query()
        ->where('user_id', $userId)
        ->where('type', 'totp')
        ->whereNull('disabled_at')
        ->count();
}

final class DispositionProbe
{
    public bool $registered = false;

    public bool $ran = false;
}

/**
 * A host listener: when a credential of $type is created, register afterCommit
 * work. By default the work throws, as a queued job dispatched afterCommit can.
 * Registered once per test even when several credentials are created.
 *
 * @param (Closure(): void)|null $work what the deferred callback does before throwing
 */
function dispositionListener(string $type = 'totp', bool $throws = true, ?Closure $work = null): DispositionProbe
{
    $probe = new DispositionProbe();

    AuthCredential::created(static function (AuthCredential $credential) use ($probe, $type, $throws, $work): void {
        if ($credential->type !== $type || $probe->registered) {
            return;
        }

        $probe->registered = true;

        DB::connection()->afterCommit(static function () use ($probe, $throws, $work): void {
            $probe->ran = true;

            if ($work !== null) {
                $work();
            }

            if ($throws) {
                throw new RuntimeException(DISPOSITION_SENTINEL);
            }
        });
    });

    return $probe;
}

function dispositionFailingListener(): DispositionProbe
{
    return dispositionListener();
}

/** Close whatever a failed commit or a stray callback left open. */
function dispositionCloseTransactions(): void
{
    while (DB::transactionLevel() > 0) {
        DB::rollBack();
    }

    $pdo = DB::connection()->getPdo();

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
}

function dispositionSibling(): AuthSession
{
    $sibling = dispositionSession(1, 'disposition-sibling');

    // Premise for every sibling assertion: it exists and is live.
    expect($sibling->fresh())->not->toBeNull()
        ->and($sibling->fresh()?->revoked_at)->toBeNull();

    return $sibling;
}

/** The sibling still exists, and was not revoked. Deleting it is not "unrevoked". */
function expectDispositionSiblingLive(AuthSession $sibling): void
{
    $fresh = $sibling->fresh();

    expect($fresh)->not->toBeNull()
        ->and($fresh?->revoked_at)->toBeNull();
}

/* ---- the case #84 is about ---------------------------------------------- */

it('reports a post-commit listener failure as state that may have changed, and committed', function (): void {
    dispositionUser();
    Exceptions::fake();
    $probe = dispositionFailingListener();

    $result = dispositionAddTotp(dispositionSession());

    // Premises: the listener really ran after a commit, and the write is durable.
    expect($probe->registered)->toBeTrue()
        ->and($probe->ran)->toBeTrue()
        ->and(dispositionActiveTotps())->toBe(1);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::PostCommitWork]);
});

it('hands over a usable secret for the TOTP credential that did commit', function (): void {
    /*
     * The credential exists. Withholding its secret leaves the user an active
     * TOTP nobody can use, and TOTP's capacity of one then refuses the retry:
     * the residue #79 removed for the pre-commit case. Usable means unrevealed
     * and matching what was stored, not merely present.
     */
    dispositionUser();
    Exceptions::fake();
    dispositionFailingListener();

    $result = dispositionAddTotp(dispositionSession());

    expect($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(1);

    $stored = AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->whereNull('disabled_at')->firstOrFail()->secret;
    $revealed = $result->secrets[0]->reveal();

    expect($stored)->toBeString();
    expect($stored)->not->toBe('');
    expect($revealed)->toContain('secret=' . (is_string($stored) ? $stored : ''));
});

it('hands over every usable recovery code that did commit', function (): void {
    dispositionUser();
    Exceptions::fake();
    $probe = dispositionListener('recovery_code');

    $result = app(CredentialSelfService::class)->addFactor(dispositionSession(), 'recovery_code', []);

    $hashes = AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')->whereNull('disabled_at')
        ->pluck('secret')->all();

    // Premises: the post-commit failure ran over a committed set of codes.
    expect($probe->ran)->toBeTrue()
        ->and($hashes)->not->toBeEmpty();

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(count($hashes));

    $matched = [];

    foreach ($result->secrets as $secret) {
        $code = $secret->reveal();

        foreach ($hashes as $index => $hash) {
            if (is_string($hash) && Hash::check($code, $hash)) {
                $matched[$index] = true;
            }
        }
    }

    // Every stored code is matched by a revealed one, so none was spent or swapped.
    expect(count($matched))->toBe(count($hashes));
});

it('reports the listener failure to the host and keeps it out of the result', function (): void {
    dispositionUser();
    Exceptions::fake();
    dispositionFailingListener();

    $result = dispositionAddTotp(dispositionSession());

    // Premise: this is the post-commit path, not some earlier refusal.
    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged);

    Exceptions::assertReported(static fn (RuntimeException $exception): bool => $exception->getMessage() === DISPOSITION_SENTINEL);

    $json = json_encode($result);

    // Control: JSON rendering succeeded, so its absence check below is real.
    expect($json)->toBeString();
    expect(json_decode((string) $json))->not->toBeNull();

    foreach ([
        'print_r' => print_r($result, true),
        'var_export' => var_export($result, true),
        'serialize' => serialize($result),
    ] as $surface => $rendered) {
        // Control: PHP names the class on these surfaces whatever the result
        // chooses to show, so each rendering is of the real object.
        expect(str_contains($rendered, 'SelfServiceResult'))->toBeTrue("{$surface} did not render the result");
    }

    foreach ([
        'print_r' => print_r($result, true),
        'var_export' => var_export($result, true),
        'json_encode' => (string) $json,
        'serialize' => serialize($result),
    ] as $surface => $rendered) {
        expect(str_contains($rendered, 'disposition-sentinel-8f3a'))->toBeFalse("{$surface} carries the diagnostic");
    }
});

it('revokes no other session on the post-commit failure path', function (): void {
    /*
     * The additive branch revokes nothing on success, and failing after
     * commit is not a reason to start. That is also why CredentialChangeFailed
     * would be a false report here.
     */
    dispositionUser();
    Exceptions::fake();
    dispositionFailingListener();
    $sibling = dispositionSibling();

    $result = dispositionAddTotp(dispositionSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged);
    expectDispositionSiblingLive($sibling);
});

/* ---- a commit whose result is unknown ----------------------------------- */

it('reports a failed commit as indeterminate and withholds the secret', function (): void {
    /*
     * The closure finished, then the COMMIT threw. Vouch cannot tell whether
     * the write landed: a connection lost mid-commit may have committed. Here
     * a TransactionCommitting listener throws, before PDO is asked at all; the
     * case below makes the engine itself refuse the commit.
     *
     * Armed only once the TOTP row exists, so only the commit of the
     * transaction holding that write throws.
     */
    dispositionUser();
    Exceptions::fake();
    $armed = new class {
        public bool $value = false;

        public bool $fired = false;
    };

    AuthCredential::created(static function (AuthCredential $credential) use ($armed): void {
        if ($credential->type === 'totp') {
            $armed->value = true;
        }
    });
    Event::listen(TransactionCommitting::class, static function () use ($armed): void {
        if ($armed->value && ! $armed->fired) {
            $armed->fired = true;

            throw new RuntimeException(DISPOSITION_SENTINEL);
        }
    });

    $result = null;

    try {
        $result = dispositionAddTotp(dispositionSession());
    } finally {
        // The failed commit leaves the PDO transaction open; close it.
        dispositionCloseTransactions();
    }

    // Premise: the commit of the enrollment's own transaction is what failed,
    // and the service returned rather than throwing.
    expect($armed->fired)->toBeTrue()
        ->and($result)->toBeInstanceOf(SelfServiceResult::class);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Indeterminate)
        // A secret for a credential that may not exist would read as success.
        ->and($result->secrets)->toBe([])
        // Whatever post-commit work was registered never ran.
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::PostCommitWork]);
});

it('reports a commit the engine refused as indeterminate', function (): void {
    /*
     * A deferred foreign key is checked at COMMIT, so the engine itself fails
     * the commit of the transaction holding the enrollment. On PostgreSQL that
     * ends the transaction, so "PDO is no longer in a transaction" is not
     * evidence of a commit: here nothing committed. MySQL has no deferred
     * constraints.
     */
    if (DB::connection()->getDriverName() === 'mysql') {
        $this->markTestSkipped('MySQL cannot defer a constraint to commit.');
    }

    dispositionUser();
    Exceptions::fake();
    DB::statement('CREATE TABLE disposition_deferred_probe (credential_id INTEGER REFERENCES auth_credentials(id) DEFERRABLE INITIALLY DEFERRED)');

    $inserted = new DispositionProbe();
    AuthCredential::created(static function (AuthCredential $credential) use ($inserted): void {
        if ($credential->type === 'totp' && ! $inserted->registered) {
            $inserted->registered = true;
            DB::table('disposition_deferred_probe')->insert(['credential_id' => 999_999_999]);
        }
    });

    $result = null;

    try {
        $result = dispositionAddTotp(dispositionSession());
    } finally {
        dispositionCloseTransactions();
        // Before DatabaseMigrations tears the schema down: PostgreSQL refuses
        // to drop auth_credentials while this table's foreign key names it.
        DB::statement('DROP TABLE IF EXISTS disposition_deferred_probe');
    }

    // Premises: the violating row was written inside the enrollment, the
    // service returned, and the enrollment really did not commit.
    expect($inserted->registered)->toBeTrue()
        ->and($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and(dispositionActiveTotps())->toBe(0);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Indeterminate)
        ->and($result->secrets)->toBe([])
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::PostCommitWork]);
});

it('does not read another connection\'s commit as the enrollment\'s', function (): void {
    /*
     * Database-wide progress (data_version, txid, WAL position) moves when ANY
     * transaction commits. An unrelated connection commits at every point it
     * can -- at BEGIN, after each enrollment statement, at COMMIT, and in the
     * rollback callbacks -- and the enrollment's own commit is then refused, so
     * no sampling window sees only the enrollment's progress. On SQLite the
     * enrollment's write lock blocks the unrelated writer once taken; those
     * attempts fail fast and are not needed, since nothing else can commit then.
     */
    $driver = DB::connection()->getDriverName();

    if ($driver === 'mysql') {
        $this->markTestSkipped('MySQL cannot defer a constraint to commit.');
    }

    if ($driver === 'sqlite' && DB::connection()->getDatabaseName() === ':memory:') {
        $this->markTestSkipped('A second connection to :memory: is a different database.');
    }

    dispositionUser();
    $session = dispositionSession();
    Exceptions::fake();
    DB::statement('CREATE TABLE disposition_progress_other (id INTEGER)');
    DB::statement('CREATE TABLE disposition_deferred_probe (credential_id INTEGER REFERENCES auth_credentials(id) DEFERRABLE INITIALLY DEFERRED)');
    config(['database.connections.disposition_other' => [
        ...config()->array('database.connections.' . DB::getDefaultConnection()),
        'busy_timeout' => 0,
    ]]);

    $other = new class {
        public bool $active = true;

        /** @var list<string> */
        public array $landed = [];

        public function commit(string $point): void
        {
            if (! $this->active) {
                return;
            }

            try {
                DB::connection('disposition_other')->table('disposition_progress_other')->insert(['id' => 1]);
                $this->landed[] = $point;
            } catch (QueryException) {
                // SQLite: the enrollment holds the write lock.
            }
        }
    };

    $enrolling = static fn (string $connection): bool => $other->active && $connection !== 'disposition_other';
    Event::listen(TransactionBeginning::class, static function (TransactionBeginning $event) use ($other, $enrolling): void {
        if ($enrolling($event->connectionName)) {
            $other->commit('begin');
            DB::connection()->afterRollBack(static fn () => $other->commit('rollback'));
        }
    });
    Event::listen(QueryExecuted::class, static function (QueryExecuted $event) use ($other, $enrolling): void {
        if ($enrolling($event->connectionName)) {
            $other->commit('statement');
        }
    });
    Event::listen(TransactionCommitting::class, static function (TransactionCommitting $event) use ($other, $enrolling): void {
        if ($enrolling($event->connectionName)) {
            $other->commit('commit');
        }
    });

    $inserted = new DispositionProbe();
    AuthCredential::created(static function (AuthCredential $credential) use ($inserted): void {
        if ($credential->type === 'totp' && ! $inserted->registered) {
            $inserted->registered = true;
            DB::table('disposition_deferred_probe')->insert(['credential_id' => 999_999_999]);
        }
    });

    $result = null;

    try {
        $result = dispositionAddTotp($session);
    } finally {
        $other->active = false;
        dispositionCloseTransactions();
        DB::purge('disposition_other');
        DB::statement('DROP TABLE IF EXISTS disposition_deferred_probe');
        DB::statement('DROP TABLE IF EXISTS disposition_progress_other');
    }

    // Premises: unrelated commits landed around the enrollment, and the
    // enrollment's own commit did not.
    expect($other->landed)->toContain('begin')
        ->and($inserted->registered)->toBeTrue()
        ->and($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and(dispositionActiveTotps())->toBe(0);

    if ($driver === 'pgsql') {
        expect($other->landed)->toContain('statement', 'commit', 'rollback');
    }

    expect($result->writeDisposition)->toBe(WriteDisposition::Indeterminate)
        ->and($result->secrets)->toBe([]);
});

it('stays committed when the failing callback had opened a transaction', function (): void {
    /*
     * The mirror of the case above: the enrollment committed, then a host
     * callback began a transaction and threw. PDO now reports a transaction in
     * progress, which says nothing about the enrollment's.
     */
    dispositionUser();
    Exceptions::fake();
    $probe = dispositionListener(work: static function (): void {
        DB::beginTransaction();
    });

    $result = null;

    try {
        $result = dispositionAddTotp(dispositionSession());
    } finally {
        dispositionCloseTransactions();
    }

    expect($probe->ran)->toBeTrue()
        ->and($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and(dispositionActiveTotps())->toBe(1);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(1);
});

it('stays committed when a host callback registered at BEGIN throws first', function (): void {
    /*
     * afterCommit callbacks run in registration order, and a host can register
     * one as the enrollment's transaction begins -- before anything the service
     * adds inside it. If that callback throws first, any evidence of the
     * commit the service planned to gather in a later callback never arrives.
     * The credential is durable, so the answer must still be Committed, with
     * its secret.
     *
     * Registered on EVERY begin, nested ones included: Laravel runs callbacks
     * by transaction record rather than in one global order, so a marker
     * hidden in a nested transaction must not be able to run ahead of this.
     * Throwing only once the TOTP row exists, and only once, so earlier
     * transactions in the flow are untouched.
     *
     * This demands evidence of the commit that no afterCommit marker or
     * TransactionCommitted listener can supply: the signal has to come from
     * the commit itself, after the engine accepted it and before callbacks run.
     */
    dispositionUser();
    Exceptions::fake();
    $created = new DispositionProbe();
    $threw = new DispositionProbe();

    AuthCredential::created(static function (AuthCredential $credential) use ($created): void {
        if ($credential->type === 'totp') {
            $created->registered = true;
        }
    });
    Event::listen(TransactionBeginning::class, static function () use ($created, $threw): void {
        DB::connection()->afterCommit(static function () use ($created, $threw): void {
            if ($created->registered && ! $threw->ran) {
                $threw->ran = true;

                throw new RuntimeException(DISPOSITION_SENTINEL);
            }
        });
    });

    $result = dispositionAddTotp(dispositionSession());

    expect($threw->ran)->toBeTrue()
        ->and(dispositionActiveTotps())->toBe(1);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::PostCommitWork])
        ->and($result->secrets)->toHaveCount(1);

    $stored = AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->whereNull('disabled_at')->firstOrFail()->secret;

    expect($result->secrets[0]->reveal())->toContain('secret=' . (is_string($stored) ? $stored : ''));
});

/*
 * The exception itself is not evidence. Its class, message and trace all say
 * where it was CONSTRUCTED or what kind it is, never whether the engine had
 * accepted the commit when it was thrown. These two cases pair with the
 * commit-failure cases above, which throw the same sentinel or a database
 * error from the other side of the commit.
 */

it('stays committed when the post-commit exception was built before the enrollment', function (): void {
    dispositionUser();
    Exceptions::fake();
    $prebuilt = new RuntimeException(DISPOSITION_SENTINEL);
    $probe = dispositionListener(throws: false, work: static function () use ($prebuilt): void {
        throw $prebuilt;
    });

    $result = dispositionAddTotp(dispositionSession());

    expect($probe->ran)->toBeTrue()
        ->and(dispositionActiveTotps())->toBe(1);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(1);
});

it('stays committed when the post-commit callback failed with a database error', function (): void {
    dispositionUser();
    Exceptions::fake();
    $probe = dispositionListener(throws: false, work: static function (): void {
        DB::select('SELECT * FROM disposition_no_such_table');
    });

    $result = dispositionAddTotp(dispositionSession());

    expect($probe->ran)->toBeTrue()
        ->and(dispositionActiveTotps())->toBe(1);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(1);
});

it('does not read a missing rollback signal as a commit', function (): void {
    /*
     * The commit fails, and a host rollback callback registered at every BEGIN
     * throws ahead of anything the service adds. Any "no rollback was seen, so
     * it committed" inference then claims a commit that did not happen.
     */
    dispositionUser();
    Exceptions::fake();
    $armed = new class {
        public bool $value = false;

        public bool $fired = false;
    };

    AuthCredential::created(static function (AuthCredential $credential) use ($armed): void {
        if ($credential->type === 'totp') {
            $armed->value = true;
        }
    });
    Event::listen(TransactionBeginning::class, static function (): void {
        DB::connection()->afterRollBack(static function (): void {
            throw new RuntimeException(DISPOSITION_SENTINEL);
        });
    });
    Event::listen(TransactionCommitting::class, static function () use ($armed): void {
        if ($armed->value && ! $armed->fired) {
            $armed->fired = true;

            throw new RuntimeException(DISPOSITION_SENTINEL);
        }
    });

    $result = null;

    try {
        $result = dispositionAddTotp(dispositionSession());
    } finally {
        dispositionCloseTransactions();
    }

    expect($armed->fired)->toBeTrue()
        ->and($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and(dispositionActiveTotps())->toBe(0);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Indeterminate)
        ->and($result->secrets)->toBe([]);
});

/*
 * Reading the rows back afterwards is not evidence either. A callback can
 * change them after the enrollment committed, and what the table says now is
 * not what the commit did. Both cases require Committed with the enrollment's
 * secrets, and every surviving credential still matched by one of them.
 */

it('stays committed when a post-commit callback deleted one of the new codes', function (): void {
    dispositionUser();
    Exceptions::fake();
    $probe = dispositionListener('recovery_code', work: static function (): void {
        $first = AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')->orderBy('id')->value('id');
        AuthCredential::query()->whereKey($first)->delete();
    });

    $result = app(CredentialSelfService::class)->addFactor(dispositionSession(), 'recovery_code', []);

    $surviving = AuthCredential::query()->where('user_id', 1)->where('type', 'recovery_code')->pluck('secret')->all();

    expect($probe->ran)->toBeTrue()
        ->and($surviving)->not->toBeEmpty();

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and(count($result->secrets))->toBe(count($surviving) + 1);

    $matched = [];

    foreach ($result->secrets as $secret) {
        $code = $secret->reveal();

        foreach ($surviving as $index => $hash) {
            if (is_string($hash) && Hash::check($code, $hash)) {
                $matched[$index] = true;
            }
        }
    }

    expect(count($matched))->toBe(count($surviving));
});

it('stays committed when a post-commit callback deleted the new credential', function (): void {
    dispositionUser();
    Exceptions::fake();
    $probe = dispositionListener(work: static function (): void {
        AuthCredential::query()->where('user_id', 1)->where('type', 'totp')->delete();
    });

    $result = dispositionAddTotp(dispositionSession());

    expect($probe->ran)->toBeTrue()
        ->and(dispositionActiveTotps())->toBe(0);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(1);
});

/* ---- the existing meanings, kept ---------------------------------------- */

it('keeps Refused, not committed, for a driver that fails before commit', function (): void {
    dispositionUser();

    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(new InterceptingFactor(
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class),
        throwAfterEnroll: true,
    ));
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);
    $sibling = dispositionSibling();

    $result = dispositionAddTotp(dispositionSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::Refused)
        ->and($result->writeDisposition)->toBe(WriteDisposition::NotCommitted)
        ->and($result->secrets)->toBe([])
        ->and($result->cleanupFailures)->toBe([])
        // The rollback #79 added: no residue survives the refusal.
        ->and(dispositionActiveTotps())->toBe(0);
    expectDispositionSiblingLive($sibling);
});

it('reports a clean additive enrollment as completed and committed', function (): void {
    dispositionUser();

    $result = dispositionAddTotp(dispositionSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(1)
        ->and($result->cleanupFailures)->toBe([])
        ->and(dispositionActiveTotps())->toBe(1);
});

it('reports refusals that precede any write as not committed', function (): void {
    dispositionUser();
    // Active, so a refusal below cannot be explained by a listener having run.
    $probe = dispositionFailingListener();

    $single = AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad('disposition-single', 64, 'a'),
        'amr' => ['pwd'],
        'acr' => 'aal1',
        'assurance_proof' => sessionProof(1, 'aal1'),
        'weakest_satisfied_at' => now(),
    ]);

    $unauthorized = dispositionAddTotp($single);
    $unknown = app(CredentialSelfService::class)->addFactor(dispositionSession(), 'no-such-factor', []);

    /*
     * StateMayHaveChanged must stay unreachable before authorization and the
     * factor lookup, or the outcome vocabulary starts telling a caller about
     * state it was never allowed to touch.
     */
    expect($unauthorized->outcome)->toBe(SelfServiceOutcome::StepUpRequired)
        ->and($unauthorized->writeDisposition)->toBe(WriteDisposition::NotCommitted)
        ->and($unknown->outcome)->toBe(SelfServiceOutcome::Refused)
        ->and($unknown->writeDisposition)->toBe(WriteDisposition::NotCommitted)
        ->and($probe->registered)->toBeFalse()
        ->and(dispositionActiveTotps())->toBe(0);
});

/* ---- inside a caller's transaction -------------------------------------- */

it('calls a nested success indeterminate, because the caller commits it', function (): void {
    /*
     * Inside a host's transaction the enrollment's "commit" only releases a
     * savepoint. Whether the credential exists is the caller's commit to
     * decide, so Committed would be a claim Vouch cannot back. The rollback
     * half shows it: the same result, and then no credential.
     */
    dispositionUser();
    $session = dispositionSession();

    DB::beginTransaction();
    $result = dispositionAddTotp($session);
    DB::rollBack();

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Indeterminate)
        ->and(dispositionActiveTotps())->toBe(0);

    $committed = DB::transaction(static fn (): SelfServiceResult => dispositionAddTotp($session));

    expect($committed->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($committed->writeDisposition)->toBe(WriteDisposition::Indeterminate)
        ->and($committed->secrets)->toHaveCount(1)
        ->and(dispositionActiveTotps())->toBe(1);
});

it('leaves a host callback deferred to the caller\'s commit', function (): void {
    dispositionUser();
    $session = dispositionSession();
    $probe = dispositionListener(throws: false);

    DB::beginTransaction();
    $result = dispositionAddTotp($session);
    $ranBeforeCallerCommit = $probe->ran;
    DB::commit();

    expect($probe->registered)->toBeTrue()
        ->and($ranBeforeCallerCommit)->toBeFalse()
        ->and($probe->ran)->toBeTrue()
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Indeterminate);
});

it('lets the caller\'s rollback discard a host callback', function (): void {
    dispositionUser();
    $session = dispositionSession();
    $probe = dispositionListener(throws: false);

    DB::beginTransaction();
    dispositionAddTotp($session);
    DB::rollBack();

    expect($probe->registered)->toBeTrue()
        ->and($probe->ran)->toBeFalse()
        ->and(dispositionActiveTotps())->toBe(0);
});

it('surfaces a host callback failure at the caller\'s commit, not inside addFactor', function (): void {
    dispositionUser();
    $session = dispositionSession();
    $probe = dispositionFailingListener();
    $result = null;

    expect(static function () use ($session, &$result): void {
        DB::transaction(static function () use ($session, &$result): void {
            $result = dispositionAddTotp($session);
        });
    })->toThrow(RuntimeException::class, DISPOSITION_SENTINEL);

    expect($probe->ran)->toBeTrue()
        ->and($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and(dispositionActiveTotps())->toBe(1);

    if (! $result instanceof SelfServiceResult) {
        throw new RuntimeException('addFactor() did not return before the caller committed.');
    }

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Indeterminate);
});

it('rolls back only its own write when it fails inside a caller\'s transaction', function (): void {
    /*
     * The enrollment needs a rollback boundary of its own. Joining the
     * caller's transaction instead would leave the enrollment's write in it,
     * to be committed by the caller after the service said NotCommitted.
     */
    dispositionUser();
    $session = dispositionSession();

    $registry = new FactorRegistry();
    $registry->register(app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class));
    $registry->register(new InterceptingFactor(
        app(\Fissible\Vouch\Factors\Drivers\TotpFactor::class),
        throwAfterEnroll: true,
    ));
    app()->when(CredentialSelfService::class)->needs(FactorRegistry::class)->give(fn () => $registry);
    app()->forgetInstance(CredentialSelfService::class);

    $result = DB::transaction(static function () use ($session): SelfServiceResult {
        AuthIdentifier::create([
            'user_id' => 2,
            'type' => 'email',
            'value' => 'caller-work@acme.example',
            'verified_at' => now(),
        ]);

        return dispositionAddTotp($session);
    });

    // Premise: the caller's own work committed, so the absence below is the
    // enrollment's rollback and not the caller's.
    expect(AuthIdentifier::query()->where('value', 'caller-work@acme.example')->exists())->toBeTrue();

    expect($result->outcome)->toBe(SelfServiceOutcome::Refused)
        ->and($result->writeDisposition)->toBe(WriteDisposition::NotCommitted)
        ->and($result->secrets)->toBe([])
        ->and(dispositionActiveTotps())->toBe(0);
});

/* ---- paths this change does not report on ------------------------------- */

it('leaves the disposition unreported on the replacing branch', function (): void {
    /*
     * The replacing branch goes through mutateCredentials(), whose outcomes
     * already carry their own meaning. Reporting a disposition there is not
     * part of #84, and a default value would be a claim nothing measured.
     */
    dispositionUser();
    $session = dispositionSession();
    dispositionAddTotp($session);

    $result = app(CredentialSelfService::class)->addFactor($session, 'totp', ['label' => 'new phone', 'replace' => true]);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->writeDisposition)->toBeNull();
});
