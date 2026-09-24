<?php

declare(strict_types=1);

use Fissible\Vouch\Credentials\CredentialCleanupStep;
use Fissible\Vouch\Factors\VerificationRequest;
use Fissible\Vouch\Factors\Drivers\PasswordFactor;
use Fissible\Vouch\Kernel\Attempt\AttemptState;
use Fissible\Vouch\Models\AuthAttempt;
use Fissible\Vouch\Support\DatabaseTime;
use OTPHP\Factory;
use Psr\Clock\ClockInterface;
use OTPHP\TOTP;
use Fissible\Vouch\Kernel\Factor\FactorKind;
use Fissible\Vouch\Kernel\Factor\FactorStrength;
use Fissible\Vouch\Kernel\Factor\SatisfiedFactor;
use Fissible\Vouch\Factors\Drivers\RecoveryCodeFactor;
use Fissible\Vouch\Factors\Drivers\TotpFactor;
use Fissible\Vouch\Models\AuthCredential;
use Fissible\Vouch\Models\AuthSession;
use Fissible\Vouch\SelfService\CredentialSelfService;
use Fissible\Vouch\Secrets\SecretAlreadyRevealed;
use Fissible\Vouch\SelfService\SelfServiceOutcome;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Fissible\Vouch\Tests\Support\Tokens\RecordingIssuer;
use Fissible\Vouch\Tokens\ActorKind;
use Fissible\Vouch\Tokens\SubjectKey;
use Fissible\Vouch\Tokens\TokenAssuranceRecord;
use Fissible\Vouch\Tokens\TokenIssuerRegistry;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

/*
 * #41. What the caller gets when cleanup fails after the credential committed.
 *
 * mutateCredentials() runs only the mutation inside its try. The second
 * sibling-revocation pass and the evidence rewrite sit outside it, so either
 * one throwing propagates -- and the enrollment material, already minted and
 * already committed, is never returned. One-time material cannot be re-read,
 * so a lost recovery-code set is a lockout, and a TOTP credential enrolled
 * against a secret nobody saw is a factor the user cannot present.
 *
 * Reporting failure would also be false. The mutation committed; the account
 * HAS the new factor. So the outcome is Completed, the material is handed back
 * exactly once, and the result records that cleanup did not finish.
 *
 * That residual has to say WHICH step failed. The two mean different things to
 * whoever cleans up after: sibling sessions still live is an access question,
 * stale assurance evidence is an authorization one, and an operator told only
 * "something failed" has to go and look.
 *
 * Deliberately no retry here. Retrying makes a user-facing call wait on work
 * whose whole purpose was to have already happened, and adds a second failure
 * surface after the credential is committed. Reliability of the cleanup is a
 * separate concern from honesty about it.
 *
 * The failure is injected at the statement, not at SessionLifecycle, which is
 * final readonly. beforeExecuting() is an established seam in this suite and
 * matches on what is being written rather than on which method writes it, so
 * it does not pin an implementation.
 */

function cleanupUser(): void
{
    app(PasswordFactor::class)->enroll(1, ['password' => 'old-password']);
}

function cleanupSession(string $binding = 'cleanup-1'): AuthSession
{
    return AuthSession::create([
        'user_id' => 1,
        'session_binding' => str_pad($binding, 64, 'c'),
        'amr' => ['pwd', 'otp'],
        'acr' => 'aal2',
        'assurance_proof' => sessionProof(1, 'aal2'),
        'weakest_satisfied_at' => now(),
    ]);
}

/**
 * Counts the statements it matched and the times it threw.
 *
 * Both numbers are the point. Matching nothing is the failure mode that turned
 * two of these tests into assertions against an untouched happy path, and the
 * match count is also what makes a retry visible: the injected failure is
 * TRANSIENT, so an implementation that quietly retried would succeed on the
 * next statement and report nothing, while the count went up.
 */
final class StatementInjector
{
    public int $matched = 0;

    public int $injected = 0;

    /** @var list<Throwable> the exact instances thrown, for identity checks */
    public array $thrown = [];
}

/**
 * Throw once, when the $occurrence-th statement matching every fragment runs.
 *
 * Registered after all fixture writes, so counting starts at the service call.
 * This does couple to SQL shape and statement order -- match on the operation,
 * the table and the changed column together, and read the returned counts
 * rather than trusting that the injection happened.
 *
 * @param list<string> $fragments every one of which the statement must contain
 */
function failOnStatement(array $fragments, int $occurrence): StatementInjector
{
    $injector = new StatementInjector();

    DB::connection()->beforeExecuting(
        function (string $query) use ($fragments, $occurrence, $injector): void {
            foreach ($fragments as $fragment) {
                if (! str_contains($query, $fragment)) {
                    return;
                }
            }

            $injector->matched++;

            if ($injector->matched === $occurrence) {
                $injector->injected++;
                $error = new RuntimeException('Cleanup failed after the credential committed.');
                $injector->thrown[] = $error;

                throw $error;
            }
        },
    );

    return $injector;
}

/** What a call logged: the rendered text, and the throwables themselves. */
final class CapturedLogs
{
    public string $rendered = '';

    /** @var list<Throwable> */
    public array $throwables = [];
}

/**
 * Everything logged during $work, as text AND as objects.
 *
 * Both, because they answer different questions and counting the text answers
 * neither reliably. One report contributes its message TWICE -- once as
 * MessageLogged::message and again inside the rendered throwable -- so "the
 * message appears twice" was true of a single report, and the assertion I built
 * on that failed a correct implementation.
 *
 * The rendered form still matters for secrecy: a secret anywhere in what
 * reaches a log is a leak, including one carried on a previous exception, which
 * is why throwables are cast and their chain walked rather than json_encoded.
 */
function logsDuring(callable $work): CapturedLogs
{
    $captured = new CapturedLogs();

    Event::listen(MessageLogged::class, function (MessageLogged $logged) use ($captured): void {
        $rendered = $logged->message;

        foreach ($logged->context as $key => $value) {
            $rendered .= ' ' . (is_string($key) ? $key : '') . ' ';

            if ($value instanceof Throwable) {
                $captured->throwables[] = $value;

                for ($error = $value; $error instanceof Throwable; $error = $error->getPrevious()) {
                    $rendered .= (string) $error;
                }

                continue;
            }

            $rendered .= print_r($value, true);
        }

        $captured->rendered .= $rendered . "\n";
    });

    $work();

    return $captured;
}

/**
 * The reported throwables carrying exactly $message.
 *
 * @return list<Throwable>
 */
function reportedWithMessage(CapturedLogs $logs, string $message): array
{
    return array_values(array_filter(
        $logs->throwables,
        static fn (Throwable $error): bool => $error->getMessage() === $message,
    ));
}


/**
 * A code generated from provisioning material, however it encodes its seed.
 *
 * Parsed rather than pattern-matched: the query string is the contract, the
 * label and parameter order are not, and percent-encoding is equally valid.
 */
function cleanupCodeFromProvisioning(string $uri): string
{
    /*
     * Loaded through the library rather than picking the seed out of the query
     * string. Reading only 'secret' and generating a DEFAULT code accepted
     * digits=8, period=60 and an https:// scheme -- material an authenticator
     * would honour and this factor would reject, which is the exact failure
     * this is here to catch.
     */
    if ($uri === '') {
        throw new RuntimeException('The provisioning material was empty.');
    }

    $otp = Factory::loadFromProvisioningUri($uri, app(ClockInterface::class));

    if (! $otp instanceof TOTP) {
        throw new RuntimeException('The provisioning material was not a TOTP URI.');
    }

    return $otp->now();
}

/** A bare attempt for presenting a code back to the factor. */
function cleanupAttempt(): AuthAttempt
{
    return AuthAttempt::create([
        'handle' => bin2hex(random_bytes(16)),
        'state' => AttemptState::FactorPending,
        'version' => 1,
        'user_id' => 1,
        'bound_context' => 'cleanup-attempt',
        'expires_at' => app(DatabaseTime::class)->deadline(600),
    ]);
}

/** Seed a human token whose recorded proof cites one recovery credential. */
function cleanupToken(string $tokenKey, int $credentialId): void
{
    app(TokenAssuranceRecord::class)->store(
        'sanctum',
        $tokenKey,
        SubjectKey::forConfiguredUser(1),
        null,
        ActorKind::Human,
        [new SatisfiedFactor(
            'recovery_code',
            (string) $credentialId,
            FactorKind::Possession,
            FactorStrength::Possession,
            false, false, false, null,
            new DateTimeImmutable('2026-08-13T10:00:00+00:00'),
        )],
    );
}

/** Register $issuer as the only token issuer. */
function cleanupIssuer(RecordingIssuer $issuer): void
{
    app()->instance(TokenIssuerRegistry::class, new TokenIssuerRegistry([$issuer]));
    app()->forgetInstance(CredentialSelfService::class);
}

/** The id of the live recovery credential $code authenticates against, if any. */
function credentialMatching(string $code): ?int
{
    foreach (AuthCredential::query()->where('user_id', 1)
        ->where('type', 'recovery_code')->whereNull('disabled_at')->get() as $credential) {
        if (is_string($credential->secret) && Hash::check($code, $credential->secret)) {
            return $credential->id;
        }
    }

    return null;
}

it('hands back the material when sibling revocation fails after the change', function (): void {
    cleanupUser();
    $session = cleanupSession();

    // The SECOND revocation pass. The first runs before the mutation and must
    // still succeed, or this would be testing the wrong failure entirely.
    $injector = failOnStatement(['revoked_reason'], 2);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    $live = AuthCredential::query()->where('user_id', 1)
        ->where('type', 'recovery_code')->whereNull('disabled_at')->count();

    expect($injector->injected)->toBe(1)
        /*
         * Exactly two revocation statements: the pass before the mutation and
         * the one that failed. A third means something retried, which the
         * owner excluded by decision -- and a retry that kept the residual
         * passed every other assertion here when measured.
         */
        ->and($injector->matched)->toBe(2)
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::SiblingRevocation]);

    /*
     * Every code, against a real credential. "Not empty" accepted one
     * fabricated code, and accepted returning only the first of the set --
     * both measured. The material is the whole point of this issue, so it is
     * checked for completeness and usability, not presence.
     */
    expect($result->secrets)->toHaveCount($live)
        ->and($live)->toBeGreaterThan(1);

    /*
     * One code per credential, each matching a DIFFERENT one. Checking that
     * every code authenticates accepted ten separately wrapped copies of the
     * first code -- every check passes, and the user holds one usable code
     * where they should hold ten.
     */
    $matched = [];

    foreach ($result->secrets as $secret) {
        $id = credentialMatching($secret->reveal());

        expect($id)->not->toBeNull()
            ->and($matched)->not->toContain($id);

        $matched[] = $id;
    }

    expect($matched)->toHaveCount($live);
});

it('hands back material that is still one-time after cleanup failed', function (): void {
    cleanupUser();
    $session = cleanupSession();

    failOnStatement(['revoked_reason'], 2);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    /*
     * Returned once, not loosened. A result that survived a cleanup failure by
     * re-wrapping its secrets into something re-readable would hand the caller
     * material it can leak twice.
     */
    $first = $result->secrets[0];
    $first->reveal();

    expect(fn (): string => $first->reveal())->toThrow(SecretAlreadyRevealed::class);
});

it('hands back a replacement authenticator when cleanup fails', function (): void {
    cleanupUser();
    app(TotpFactor::class)->enroll(1, ['label' => 'ada@acme.example']);
    $session = cleanupSession();

    // The other minting path. Replacement had no injected-failure coverage,
    // and it mints a secret the user must scan exactly once.
    $injector = failOnStatement(['revoked_reason'], 2);

    $result = app(CredentialSelfService::class)
        ->addFactor($session, 'totp', ['label' => 'ada@acme.example', 'replace' => true]);

    // Counts here as well: retrying only the replacement's cleanup, and keeping
    // its residual, passed everything else in this file.
    expect($injector->matched)->toBe(2)
        ->and($injector->injected)->toBe(1);

    $credential = AuthCredential::query()->where('user_id', 1)->where('type', 'totp')
        ->whereNull('disabled_at')->sole();

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::SiblingRevocation])
        ->and($result->secrets)->toHaveCount(1);

    /*
     * Used, not matched. Asking whether the stored seed appears as a SUBSTRING
     * was wrong in both directions at once: a URI carrying the real seed in its
     * label while offering a different one as the secret passed, and correctly
     * percent-encoding the seed failed. Neither says anything about whether the
     * user can authenticate.
     *
     * So the material is parsed through the library, a code generated from the
     * settings it declares, and that code presented to the factor -- the only
     * question worth asking about something handed over exactly once.
     */
    $code = cleanupCodeFromProvisioning($result->secrets[0]->reveal());

    /*
     * verify() re-resolves the user's live TOTP credential rather than using
     * the one passed, so the sole() above is what keeps this unambiguous. The
     * resolved id is asserted to say that out loud instead of leaving it to the
     * fixture.
     */
    $verified = app(TotpFactor::class)->verify(new VerificationRequest(
        attempt: cleanupAttempt(),
        input: ['code' => $code],
        credential: $credential->refresh(),
    ));

    expect($verified->failure)->toBeNull()
        ->and($verified->factor?->credentialId)->toBe((string) $credential->id);
});

it('hands back the change when the evidence rewrite fails after it', function (): void {
    cleanupUser();
    $totp = app(TotpFactor::class)->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];

    /*
     * The session's proof must CITE the credential being removed. A proof that
     * does not mention it leaves the rewrite with nothing to change, so it
     * returns early, writes nothing, and the failure this test injects never
     * happens -- which it did, silently, until the statement never fired.
     */
    $session = cleanupSession();
    $session->update(['assurance_proof' => sessionProofFrom(1, [
        evidenceFactor('password', credentialId: stringValue(AuthCredential::query()
            ->where('user_id', 1)->where('type', 'password')->value('id'))),
        evidenceFactor('totp', credentialId: (string) $totp->id),
    ])]);

    // The evidence rewrite is the only writer of assurance_proof in this call.
    $injector = failOnStatement(['assurance_proof'], 1);

    $result = app(CredentialSelfService::class)->removeFactor($session, $totp->id);

    /*
     * Read the counts here too. Pinning no-retries only on the revocation site
     * left a retry of the EVIDENCE rewrite surviving, and the injection being
     * transient means such a retry succeeds silently.
     */
    expect($injector->injected)->toBe(1)
        ->and($injector->matched)->toBe(1);

    /*
     * Removal mints nothing, so there is no material to lose -- but the
     * credential is gone and the caller must not be told otherwise. The
     * residual names the evidence rewrite rather than the revocation, because
     * what is left stale is the session's assurance, not its liveness.
     */
    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->toBe([])
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::EvidenceCleanup])
        ->and(AuthCredential::query()->whereKey($totp->id)->whereNull('disabled_at')->exists())
        ->toBeFalse();
});

it('reports no residual when cleanup finishes', function (): void {
    cleanupUser();
    $sibling = cleanupSession('sibling');
    $session = cleanupSession('acting');

    /*
     * The paired negative. Without it an implementation that always reported a
     * residual would pass both tests above and tell every caller their other
     * sessions might still be live.
     */
    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    expect($result->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($result->secrets)->not->toBe([])
        ->and($result->cleanupFailures)->toBe([])
        ->and($sibling->refresh()->revoked_at)->not->toBeNull();
});

it('keeps the minted material out of the residual', function (): void {
    cleanupUser();
    $session = cleanupSession();

    $injector = failOnStatement(['revoked_reason'], 2);

    $result = null;
    $logs = logsDuring(function () use ($session, &$result): void {
        $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);
    });

    $result ??= throw new RuntimeException('The call returned nothing.');

    /*
     * The material is bearer credential. It belongs in the response the caller
     * renders once and nowhere else -- not in a residual, not in whatever an
     * operator serializes to look at one, and not in a log line written on the
     * way past. Revealing and re-wrapping the codes put plaintext in the log
     * while passing a residual-only check, measured.
     *
     * The WHOLE result, not just the residual: a secret parked anywhere else
     * on it travels just as far.
     *
     * JSON_THROW_ON_ERROR because a failed json_encode() returns false, which
     * concatenates to nothing -- an unbacked enum made this pass by being
     * unserializable rather than by being clean.
     */
    $rendered = print_r($result, true)
        . json_encode($result->cleanupFailures, JSON_THROW_ON_ERROR)
        /*
         * The result itself, not its property bag. get_object_vars() walks
         * round whatever jsonSerialize() the result defines, which is exactly
         * where a serializer leak lives -- one survived this check. No partial
         * output either: a serialization error must fail rather than quietly
         * produce a shorter string with nothing to match.
         */
        . json_encode($result, JSON_THROW_ON_ERROR);

    // Not vacuous: the loop below proves nothing if the secrets went missing,
    // and their absence is a different failure this file already covers.
    expect($result->secrets)->not->toBe([]);

    foreach ($result->secrets as $secret) {
        $code = $secret->reveal();

        expect($rendered)->not->toContain($code)
            ->and($logs->rendered)->not->toContain($code);
    }

    expect($rendered)->not->toContain('Cleanup failed after the credential committed.');

    /*
     * The other half of the owner's boundary, asserted separately: the result
     * stays clean AND the operator still gets the error. report() remains the
     * path to a stack and a message, so a cleanup failure nobody can see is
     * not the privacy win it looks like.
     */
    expect($logs->rendered)->toContain('Cleanup failed after the credential committed.')
        /*
         * The THROWABLE, not a message copied out of it. Replacing report()
         * with Log::error($throwable->getMessage()) preserved this text while
         * losing the class, the file and the stack -- everything an operator
         * would actually use. The rendered form of a reported exception
         * carries its class name and a numbered frame.
         */
        /*
         * The THROWABLE, asserted as an object. Replacing report() with
         * Log::error($throwable->getMessage()) preserved the text while losing
         * the class, the file and the stack -- everything an operator uses.
         *
         * Not a '#0 ' substring: that marker belongs to one Monolog formatter
         * and vanishes under another, so it would pin the log configuration
         * rather than the reporting.
         */
        ->and(reportedWithMessage($logs, 'Cleanup failed after the credential committed.'))
        ->toHaveCount(1);

    /*
     * The same OBJECT, not one that looks like it. Counting accepted reporting
     * a re-wrapped RuntimeException carrying only the message, which loses the
     * original's file, line and cause -- the diagnostic context is the entire
     * reason the operator path exists.
     *
     * Identity also replaces a getTrace() check, which was unsound: a legitimately
     * reported throwable can have zero frames.
     */
    expect($logs->throwables)->toContain($injector->thrown[0]);
});

it('reports both cleanup steps when both fail', function (): void {
    cleanupUser();
    $totp = app(TotpFactor::class)->enroll(1, ['label' => 'ada@acme.example'])->credentials[0];
    $session = cleanupSession();
    $session->update(['assurance_proof' => sessionProofFrom(1, [
        evidenceFactor('password', credentialId: stringValue(AuthCredential::query()
            ->where('user_id', 1)->where('type', 'password')->value('id'))),
        evidenceFactor('totp', credentialId: (string) $totp->id),
    ])]);

    $revocation = failOnStatement(['revoked_reason'], 2);
    $evidence = failOnStatement(['assurance_proof'], 1);

    /*
     * The owner's wording is "sibling-revocation and/or evidence-cleanup
     * failure", so a failure in the first must not cancel the second. An
     * implementation that abandons the rest of cleanup on the first throw
     * reports one step and silently skips work nobody knows was skipped.
     */
    $result = null;
    $logs = logsDuring(function () use ($session, $totp, &$result): void {
        $result = app(CredentialSelfService::class)->removeFactor($session, $totp->id);
    });

    $result ??= throw new RuntimeException('The call returned nothing.');

    expect($revocation->injected)->toBe(1)
        ->and($evidence->injected)->toBe(1)
        /*
         * BOTH failures reported, not just the first. Suppressing only the
         * evidence report kept every other assertion here true while an
         * operator saw half of what went wrong.
         */
        /*
         * BOTH failures reported, counted as objects. Suppressing only the
         * evidence report left every other assertion true while an operator saw
         * half of what went wrong -- and counting occurrences of the message in
         * text could not see it, since one report contributes the text twice.
         */
        ->and(reportedWithMessage($logs, 'Cleanup failed after the credential committed.'))
        ->toHaveCount(2)
        /*
         * Each original, by identity. Reporting the sibling exception TWICE
         * while omitting the evidence one satisfied the count while hiding half
         * the failure -- measured.
         */
        ->and($logs->throwables)->toContain($revocation->thrown[0])
        ->and($logs->throwables)->toContain($evidence->thrown[0])
        ->and($result->outcome)->toBe(SelfServiceOutcome::Completed)
        // The set, not the order. Both failures carry the same information
        // whichever way round they are listed, and pinning the order rejects
        // an implementation that differs in nothing that matters.
        ->and($result->cleanupFailures)->toHaveCount(2)
        ->and($result->cleanupFailures)->toContain(CredentialCleanupStep::SiblingRevocation)
        ->and($result->cleanupFailures)->toContain(CredentialCleanupStep::EvidenceCleanup);
});

it('keeps driver residuals and cleanup residuals apart', function (): void {
    cleanupUser();
    $session = cleanupSession();

    $code = app(RecoveryCodeFactor::class)->enroll(1, [])->credentials[0];
    cleanupToken('token-key-1', $code->id);

    $issuer = new RecordingIssuer('sanctum', new RuntimeException('Issuer unreachable.'));
    cleanupIssuer($issuer);

    failOnStatement(['revoked_reason'], 2);

    /*
     * BOTH failing at once, which is the only arrangement that separates them.
     * With no driver failure present, an implementation that drops driver
     * residuals whenever cleanup fails passed -- there was nothing to drop.
     *
     * They mean different things: a token left live at its issuer is someone
     * else's system to reconcile, cleanup Vouch owns that did not finish is
     * this one's. Collapsing them leaves an operator not knowing where to look.
     */
    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    expect($issuer->attempted)->toContain('token-key-1')
        ->and($result->cleanupFailures)->toBe([CredentialCleanupStep::SiblingRevocation])
        ->and($result->driverFailures)->toHaveCount(1)
        ->and($result->driverFailures[0]->tokenKey)->toBe('token-key-1');
});

it('does not carry one call\'s cleanup residual into the next', function (): void {
    cleanupUser();
    $session = cleanupSession();

    failOnStatement(['revoked_reason'], 2);

    $service = app(CredentialSelfService::class);

    $first = $service->regenerateRecoveryCodes($session);
    $second = $service->regenerateRecoveryCodes($session);

    /*
     * The injection is transient, so the second call's cleanup succeeds. A
     * residual accumulated on the service rather than built per call reports
     * the first failure again and sends an operator after sessions that were
     * revoked correctly.
     */
    expect($first->cleanupFailures)->toBe([CredentialCleanupStep::SiblingRevocation])
        ->and($second->outcome)->toBe(SelfServiceOutcome::Completed)
        ->and($second->cleanupFailures)->toBe([]);
});

it('still fails the change when the mutation itself fails', function (): void {
    cleanupUser();
    $session = cleanupSession();

    /*
     * Inside the mutation, not after it. This is the #35 contract and it is
     * unchanged: nothing committed, so nothing is handed back.
     *
     * The insert, not the factor id -- 'recovery_code' travels as a binding
     * rather than as SQL text, so matching on it matched nothing and this test
     * silently asserted against an untouched happy path.
     */
    failOnStatement(['insert', 'auth_credentials'], 1);

    $result = app(CredentialSelfService::class)->regenerateRecoveryCodes($session);

    expect($result->outcome)->toBe(SelfServiceOutcome::CredentialChangeFailed)
        ->and($result->secrets)->toBe([])
        ->and($result->cleanupFailures)->toBe([]);
});
