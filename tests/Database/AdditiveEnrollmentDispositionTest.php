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
use Illuminate\Database\Events\TransactionCommitting;
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

    foreach ([
        'print_r' => print_r($result, true),
        'var_export' => var_export($result, true),
        'json_encode' => (string) json_encode($result),
        'serialize' => serialize($result),
    ] as $surface => $rendered) {
        // Control: each rendering is of the real result object.
        expect($rendered)->toContain('writeDisposition');
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
    }

    // Premises: the violating row was written inside the enrollment, the
    // service returned, and the enrollment really did not commit.
    expect($inserted->registered)->toBeTrue()
        ->and($result)->toBeInstanceOf(SelfServiceResult::class)
        ->and(dispositionActiveTotps())->toBe(0);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Indeterminate)
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
