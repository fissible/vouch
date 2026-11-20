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

/**
 * A host listener: when a credential is created, register afterCommit work
 * that throws. Returns a probe recording whether it really fired.
 */
function dispositionFailingListener(): stdClass
{
    $probe = new stdClass();
    $probe->registered = false;
    $probe->threw = false;

    AuthCredential::created(static function (AuthCredential $credential) use ($probe): void {
        if ($credential->type !== 'totp') {
            return;
        }

        $probe->registered = true;

        DB::connection()->afterCommit(static function () use ($probe): void {
            $probe->threw = true;

            throw new RuntimeException(DISPOSITION_SENTINEL);
        });
    });

    return $probe;
}

/* ---- the case #84 is about ---------------------------------------------- */

it('reports a post-commit listener failure as state that may have changed, and committed', function (): void {
    dispositionUser();
    Exceptions::fake();
    $probe = dispositionFailingListener();

    $result = dispositionAddTotp(dispositionSession());

    // Premises: the listener really ran after a commit, and the write is durable.
    expect($probe->registered)->toBeTrue()
        ->and($probe->threw)->toBeTrue()
        ->and(dispositionActiveTotps())->toBe(1);

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::PostCommitWork]);
});

it('hands over the secret of a credential that did commit', function (): void {
    /*
     * The credential exists. Withholding its secret leaves the user an active
     * TOTP nobody can use, and TOTP's capacity of one then refuses the retry:
     * the residue #79 removed for the pre-commit case.
     */
    dispositionUser();
    Exceptions::fake();
    dispositionFailingListener();

    $result = dispositionAddTotp(dispositionSession());

    expect($result->writeDisposition)->toBe(WriteDisposition::Committed)
        ->and($result->secrets)->toHaveCount(1);
});

it('reports the listener failure to the host and keeps it out of the result', function (): void {
    dispositionUser();
    Exceptions::fake();
    dispositionFailingListener();

    $result = dispositionAddTotp(dispositionSession());

    // Premise: this is the post-commit path, not some earlier refusal.
    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged);

    Exceptions::assertReported(static fn (RuntimeException $exception): bool => $exception->getMessage() === DISPOSITION_SENTINEL);

    $rendered = print_r($result, true);

    // Control: the rendering is the real result, so an absence below means something.
    expect($rendered)->toContain('StateMayHaveChanged')
        ->and($rendered)->not->toContain('disposition-sentinel-8f3a');
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
    $sibling = dispositionSession(1, 'disposition-sibling');

    $result = dispositionAddTotp(dispositionSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::StateMayHaveChanged)
        ->and($result->outcome)->not->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($sibling->fresh()?->revoked_at)->toBeNull();
});

/* ---- a commit whose result is unknown ----------------------------------- */

it('reports a failed commit as indeterminate and withholds the secret', function (): void {
    /*
     * The closure finished, then the COMMIT threw. Vouch cannot tell whether
     * the write landed: a connection lost mid-commit may have committed. A
     * TransactionCommitting listener stands in for that failure, because no
     * engine lets a test force a commit to fail on demand.
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
        $pdo = DB::connection()->getPdo();

        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
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
    $sibling = dispositionSession(1, 'disposition-sibling');

    $result = dispositionAddTotp(dispositionSession());

    expect($result->outcome)->toBe(SelfServiceOutcome::Refused)
        ->and($result->writeDisposition)->toBe(WriteDisposition::NotCommitted)
        ->and($result->secrets)->toBe([])
        ->and($result->cleanupFailures)->toBe([])
        // The rollback #79 added: no residue survives the refusal.
        ->and(dispositionActiveTotps())->toBe(0)
        ->and($sibling->fresh()?->revoked_at)->toBeNull();
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
