<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\Identifiers\IdentifierCollisionsFound;
use Fissible\Vouch\Identifiers\IdentifierEqualityUpgrade;
use Fissible\Vouch\Console\RetentionManifest;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Support\DatabaseTime;
use Fissible\Vouch\Throttle\IdentifierCanonicalizer;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

uses(DatabaseMigrations::class);

/*
 * #14 and #15, together, because #15's sweep destroys #14's evidence.
 *
 * The retention manifest guard named six tables with no reclaimer on its first run. Five of them are
 * here; the two anchor tables are #16 and #17 and are a different question.
 *
 * #14 IS NOT A NEW POLICY. `auth_identifier_verification_outbox` and `auth_recovery_proof_outbox`
 * have the same columns as the pruned `auth_challenge_outbox`, carry the same OtpOutboxStatus
 * vocabulary, and are written by the same shape of delivery code. The policy was ratified for the
 * OTP outbox and these two were missed: delete where `expires_at <= database_now`, classifying
 * delivered against undelivered as it goes.
 *
 * #15 IS a decision, and it is that the ceremony row is not the durable fact. A verification, a
 * recovery proof and a link request are short-lived challenges with an expiry; what outlasts them
 * lives in a different table that is already declared retained -- a verified binding is
 * `auth_identifiers.verified_at`, a completed link is a row in `auth_federated_identities`. Keeping
 * the ceremony forever does not make the binding more durable, it only retains identity evidence
 * about a person with no stated purpose, which is what `unreclaimed()` was flagging.
 *
 * So the predicate is the one the package already uses for an expiring row: expiry. Not "consumed",
 * because a consumed row is still the replay defence for its own code until it expires, and
 * `auth_attempts` sets that precedent -- it is pruned on `expires_at <= now` whatever state it
 * reached.
 *
 * THE ORDERING HAZARD, which is why one file and not two. Both outboxes cascade on their parent:
 * `verification_id` and `proof_id` are both `cascadeOnDelete()`. So if #15's parent sweep runs
 * first, #14's rows are gone before they are counted, and the delivered/undelivered figures an
 * operator relies on silently read zero. The existing OTP reclaimer already orders itself this way
 * for `auth_challenge_outbox` against `auth_attempts`, and the comment there says so.
 *
 * DatabaseMigrations rather than RefreshDatabase, following the other prune tests: the command runs
 * its own transaction and the counts asserted here are committed affected-row results.
 */

/** A past instant on the database clock, so the fixtures expire by the same clock the sweep reads. */
function ceremonyPast(int $seconds = 60): string
{
    return app(DatabaseTime::class)->current()->modify('-' . $seconds . ' seconds')->format('Y-m-d H:i:s');
}

/** A future instant, for the rows every case below requires to survive. */
function ceremonyFuture(int $seconds = 3600): string
{
    return app(DatabaseTime::class)->current()->modify('+' . $seconds . ' seconds')->format('Y-m-d H:i:s');
}

/**
 * A verification row.
 *
 * `created_at` is deliberately OLD and independent of `expires_at`, because a fixture that equates
 * them cannot tell an `expires_at` reclaimer from a `created_at` one: measured, a mutant deleting on
 * `created_at` passed every case while they matched.
 *
 * @param  array<string, string|null>  $terminal
 */
function seedVerification(string $expiresAt, array $terminal = [], string $value = 'ada@example.test'): int
{
    return (int) DB::table('auth_identifier_verifications')->insertGetId(array_merge([
        'identifier_type' => 'email',
        'identifier_value' => $value,
        'code_hash' => hash('sha256', $value . $expiresAt),
        'is_decoy' => 0,
        'attempts' => 0,
        'expires_at' => $expiresAt,
        'created_at' => ceremonyPast(86400 * 30),
        'updated_at' => ceremonyPast(86400 * 30),
    ], $terminal));
}

/** @param array<string, string|null> $terminal */
function seedRecoveryProof(string $expiresAt, array $terminal = [], string $value = 'ada@example.test'): int
{
    return (int) DB::table('auth_recovery_proofs')->insertGetId(array_merge([
        'identifier_type' => 'email',
        'identifier_value' => $value,
        'code_hash' => hash('sha256', 'proof' . $value . $expiresAt),
        'is_decoy' => 0,
        'attempts' => 0,
        'expires_at' => $expiresAt,
        'created_at' => ceremonyPast(86400 * 30),
        'updated_at' => ceremonyPast(86400 * 30),
    ], $terminal));
}

function seedOutbox(string $table, string $parentColumn, int $parentId, string $expiresAt, OtpOutboxStatus $status): int
{
    return (int) DB::table($table)->insertGetId([
        'opaque_id' => bin2hex(random_bytes(32)),
        $parentColumn => $parentId,
        'payload' => null,
        'status' => $status->value,
        'expires_at' => $expiresAt,
        // Creation independent of expiry, so a reclaimer using created_at is distinguishable.
        'created_at' => ceremonyPast(86400 * 30),
        'updated_at' => ceremonyPast(86400 * 30),
    ]);
}

/**
 * A link request, with the federated identity it points at -- which must OUTLIVE it.
 *
 * `proven_at` and the identity's `user_id` are populated so this represents a COMPLETED link rather
 * than an abandoned one: without them the outcome assertion had no outcome to preserve.
 */
function seedLinkRequest(string $expiresAt, bool $proven = true): int
{
    $old = ceremonyPast(86400 * 30);

    $connection = (int) DB::table('auth_connections')->insertGetId([
        'trust_email_verified' => 0,
        'auto_link' => 0,
        'created_at' => $old,
        'updated_at' => $old,
    ]);

    $identity = (int) DB::table('auth_federated_identities')->insertGetId([
        'connection_id' => $connection,
        'issuer' => 'https://issuer.example.test',
        'subject' => 'subject-' . $expiresAt,
        'user_id' => 7,
        'created_at' => $old,
        'updated_at' => $old,
    ]);

    return (int) DB::table('auth_link_requests')->insertGetId([
        'user_id' => 7,
        'federated_identity_id' => $identity,
        'proven_at' => $proven ? $old : null,
        'expires_at' => $expiresAt,
        'created_at' => $old,
        'updated_at' => $old,
    ]);
}

/**
 * The three ceremony kinds, each as the pieces every case needs.
 *
 * One match rather than names threaded through a dataset: a dataset of callables is not provably
 * callable at level 9, and a dataset of table names had each test re-deriving which parent went
 * with which outbox.
 *
 * @return array{parent: string, outbox: string|null, parentColumn: string|null}
 */
function ceremonyShape(string $kind): array
{
    return match ($kind) {
        'verification' => [
            'parent' => 'auth_identifier_verifications',
            'outbox' => 'auth_identifier_verification_outbox',
            'parentColumn' => 'verification_id',
        ],
        'proof' => [
            'parent' => 'auth_recovery_proofs',
            'outbox' => 'auth_recovery_proof_outbox',
            'parentColumn' => 'proof_id',
        ],
        'link' => ['parent' => 'auth_link_requests', 'outbox' => null, 'parentColumn' => null],
        default => throw new RuntimeException('Unknown ceremony kind ' . $kind . '.'),
    };
}

/** @param array<string, string|null> $terminal */
function seedCeremony(string $kind, string $expiresAt, array $terminal = []): int
{
    return match ($kind) {
        'verification' => seedVerification($expiresAt, $terminal),
        'proof' => seedRecoveryProof($expiresAt, $terminal),
        'link' => seedLinkRequest($expiresAt),
        default => throw new RuntimeException('Unknown ceremony kind ' . $kind . '.'),
    };
}

function prune(): int
{
    return Artisan::call('vouch:prune');
}

/* ---- #14: the two outboxes the policy already covered -------------------- */

it('reclaims an expired delivery row from an outbox that had no reclaimer', function (string $kind): void {
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];
    $parent = seedCeremony($kind, ceremonyFuture());

    seedOutbox($outbox, (string) $shape['parentColumn'], $parent, ceremonyPast(), OtpOutboxStatus::Delivered);

    expect(DB::table($outbox)->count())->toBe(1);

    prune();

    expect(DB::table($outbox)->count())->toBe(0);

    // The parent is NOT expired, so the row went on its own expiry rather than by cascade.
    expect(DB::table($shape['parent'])->count())->toBe(1);
})->with(['verification', 'proof']);

it('leaves a delivery row that has not expired, whatever status it carries', function (string $kind, string $status): void {
    /*
     * The non-vacuity control for every deletion below -- a sweep that emptied the table would pass
     * all of them -- and it covers every status, not just pending. A selector written as
     * `expires_at <= now OR status != pending` satisfies a pending-only fixture while prematurely
     * deleting delivered and undeliverable rows that have not expired.
     */
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];

    seedOutbox($outbox, (string) $shape['parentColumn'], seedCeremony($kind, ceremonyFuture()), ceremonyFuture(), OtpOutboxStatus::from($status));

    prune();

    expect(DB::table($outbox)->count())->toBe(1);
})->with([
    ['verification', 'pending'],
    ['verification', 'delivered'],
    ['verification', 'undeliverable'],
    ['proof', 'pending'],
    ['proof', 'delivered'],
    ['proof', 'undeliverable'],
]);

it('reports an expired undelivered row from either outbox as delivery health', function (string $kind): void {
    /*
     * The operational signal AND the work. An expired-undelivered OTP row already sets a distinct
     * exit code, because it means a delivery worker stopped doing its job; a recovery proof or
     * identifier verification that expired undelivered says the same thing.
     *
     * Measured: asserting only the exit code and the word "undelivered" proved almost nothing --
     * mutants that left the expired pending row behind, ignored undeliverable rows entirely, or
     * classified delivered rows as undelivered all passed, because the existing zero-count OTP
     * summary already contains that word. So the row must be gone and the figures must be exact.
     */
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];
    $column = (string) $shape['parentColumn'];
    $live = seedCeremony($kind, ceremonyFuture());

    seedOutbox($outbox, $column, $live, ceremonyPast(), OtpOutboxStatus::Pending);
    seedOutbox($outbox, $column, $live, ceremonyPast(), OtpOutboxStatus::Undeliverable);
    seedOutbox($outbox, $column, $live, ceremonyPast(), OtpOutboxStatus::Delivered);
    seedOutbox($outbox, $column, $live, ceremonyFuture(), OtpOutboxStatus::Pending);

    expect(prune())->toBe(CommandExit::DeliveryHealth->value);

    $output = Artisan::output();

    /*
     * The figures themselves are prose: vouch:prune has no structured output, so asserting them
     * means asserting wording the implementation should be free to choose -- and a bare-number
     * regex accepts a wrong figure anyway, since any other count in the summary satisfies it.
     *
     * What is asserted is the signal, the work, and that the output NAMES this table: an operator
     * who cannot see which outbox was swept learns nothing from the warning.
     *
     * The cost is accepted and stated rather than hidden: with no figure asserted, a reclaimer whose
     * counter is simply wrong -- an increment replaced by an assignment, say -- still satisfies
     * everything here. Closing that needs a figure bound to its own outbox and category, which means
     * either pinning the summary's wording or giving vouch:prune structured output. The second is
     * the right answer and is a separate change; until then the deletions are what this file
     * guarantees, and the figures are not.
     */
    expect($output)->toContain('undelivered');
    expect($output)->toContain($kind === 'verification' ? 'verification' : 'recovery');

    // Only the unexpired one survives, so neither a leftover nor an over-eager sweep passes.
    expect(DB::table($outbox)->count())->toBe(1);
    expect(DB::table($outbox)->where('expires_at', '>', ceremonyPast())->count())->toBe(1);
})->with(['verification', 'proof']);

it('reports delivery health for an outbox holding only undeliverable rows', function (string $kind): void {
    /*
     * Undeliverable on its own, with no pending row anywhere. A classification that counted only
     * pending rows as undelivered would exit clean here while an operator's delivery worker was
     * failing every send -- and the mixed case cannot catch it, because its pending row carries the
     * signal by itself.
     */
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];

    seedOutbox($outbox, (string) $shape['parentColumn'], seedCeremony($kind, ceremonyFuture()), ceremonyPast(), OtpOutboxStatus::Undeliverable);

    expect(prune())->toBe(CommandExit::DeliveryHealth->value);
    expect(DB::table($outbox)->count())->toBe(0);
})->with(['verification', 'proof']);

it('exits cleanly when every expired delivery row was delivered', function (string $kind): void {
    /*
     * The other side of the signal: delivery health must not fire for rows that did their job.
     * Measured, a mutant classifying delivered rows as undelivered passed while only the failing
     * case was asserted.
     */
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];

    seedOutbox($outbox, (string) $shape['parentColumn'], seedCeremony($kind, ceremonyFuture()), ceremonyPast(), OtpOutboxStatus::Delivered);

    expect(prune())->toBe(0);
    expect(DB::table($outbox)->count())->toBe(0);
})->with(['verification', 'proof']);

/* ---- #15: the ceremony rows --------------------------------------------- */

it('reclaims an expired ceremony row', function (string $kind): void {
    $table = ceremonyShape($kind)['parent'];
    seedCeremony($kind, ceremonyPast());

    expect(DB::table($table)->count())->toBe(1);

    prune();

    expect(DB::table($table)->count())->toBe(0);
})->with(['verification', 'proof', 'link']);

it('leaves a ceremony row that has not expired', function (string $kind): void {
    $table = ceremonyShape($kind)['parent'];
    seedCeremony($kind, ceremonyFuture());

    prune();

    expect(DB::table($table)->count())->toBe(1);
})->with(['verification', 'proof', 'link']);

it('keeps the durable fact when the ceremony that produced it is reclaimed', function (): void {
    /*
     * The heart of #15. The manifest's old reason was that these rows are "durable identity
     * evidence", which conflates the ceremony with its outcome: a verified binding is
     * `auth_identifiers.verified_at` and a completed link is a row in `auth_federated_identities`,
     * both already declared retained. If reclaiming the ceremony took the outcome with it, the
     * decision would be wrong and this is what would say so.
     *
     * Compared by VALUE, not by count. Measured: a mutant that rewrote verified_at and the federated
     * identity's ownership passed while only rows were counted.
     */
    $verifiedAt = ceremonyPast(86400 * 7);

    DB::table('auth_identifiers')->insert([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'ada@example.test',
        'verified_at' => $verifiedAt,
        'is_primary' => 1,
        'created_at' => $verifiedAt,
        'updated_at' => $verifiedAt,
    ]);

    seedVerification(ceremonyPast(), ['consumed_at' => ceremonyPast(120)]);
    seedLinkRequest(ceremonyPast());

    $identifiersBefore = DB::table('auth_identifiers')->orderBy('id')->get()->map(fn (object $r): array => (array) $r)->all();
    $identitiesBefore = DB::table('auth_federated_identities')->orderBy('id')->get()->map(fn (object $r): array => (array) $r)->all();

    prune();

    expect(DB::table('auth_identifier_verifications')->count())->toBe(0);
    expect(DB::table('auth_link_requests')->count())->toBe(0);

    // The outcomes, byte for byte.
    expect(DB::table('auth_identifiers')->orderBy('id')->get()->map(fn (object $r): array => (array) $r)->all())
        ->toBe($identifiersBefore);
    expect(DB::table('auth_federated_identities')->orderBy('id')->get()->map(fn (object $r): array => (array) $r)->all())
        ->toBe($identitiesBefore);
});

it('keeps a recovery grace window when the proof that opened it is reclaimed', function (): void {
    /*
     * The longer-lived outcome of a recovery proof, which the first form of this file missed
     * entirely: the proof opens a grace window on the SESSION, and the credential change happens
     * under that window rather than under the proof. So the session's
     * `recovery_grace_expires_at` must outlive the proof row, or reclaiming the proof would end a
     * recovery that is still legitimately in progress.
     */
    $grace = ceremonyFuture(1800);
    $old = ceremonyPast(86400);

    DB::table('auth_sessions')->insert([
        'session_binding' => str_repeat('s', 64),
        'user_id' => 7,
        'acr' => 'aal1',
        'recovery_grace_expires_at' => $grace,
        'created_at' => $old,
        'updated_at' => $old,
    ]);

    seedRecoveryProof(ceremonyPast(), ['consumed_at' => ceremonyPast(120)]);

    prune();

    expect(DB::table('auth_recovery_proofs')->count())->toBe(0);

    $session = DB::table('auth_sessions')->where('session_binding', str_repeat('s', 64))->first();

    expect($session)->not->toBeNull();
    expect(substr((string) ((array) $session)['recovery_grace_expires_at'], 0, 19))->toBe($grace);
});

it('no longer gives the identifier collision upgrade a consumed proof to refuse over', function (): void {
    /*
     * The consequence of #15, EXERCISED rather than described.
     *
     * IdentifierEqualityUpgrade treats these tables as `transient`: a collision whose rows are not
     * terminal it deletes, and one holding a CONSUMED or BURNED proof it refuses over, raising
     * IdentifierCollisionsFound so an operator resolves it. Reclaiming an expired consumed row
     * removes that evidence, so the upgrade sees no collision and proceeds.
     *
     * Asserted both ways round -- refusal before, success after -- because describing it proves
     * nothing: an earlier form of this test only counted the deleted rows and would have passed
     * whatever the upgrade did.
     *
     * The consequence is accepted, and the ordering that makes it safe is a DEPLOYMENT requirement
     * rather than a property of the scheduler: a scheduler running newly deployed code can prune
     * before the migration, or between a refused migration and its retry. docs/operations.md has to
     * say that pruning stays paused until the upgrade has completed successfully.
     */
    $upgrade = static fn (): IdentifierEqualityUpgrade => new IdentifierEqualityUpgrade(
        DB::connection(),
        new IdentifierCanonicalizer(),
    );

    // Two spellings of one address, both consumed and both expired: the shape it refuses over.
    seedVerification(ceremonyPast(), ['consumed_at' => ceremonyPast(120)], 'ADA@example.test');
    seedVerification(ceremonyPast(), ['consumed_at' => ceremonyPast(120)], 'ada@example.test');

    /*
     * Required, not skipped. An earlier form skipped when the upgrade unexpectedly succeeded, so a
     * regression that stopped refusing over consumed collisions would have skipped the whole
     * interaction check rather than failing it. These two spellings canonicalize identically on
     * every supported engine, so the refusal is stageable everywhere and its absence is a defect.
     */
    expect(fn () => $upgrade()->apply())->toThrow(IdentifierCollisionsFound::class);

    prune();

    expect(DB::table('auth_identifier_verifications')->count())->toBe(0);

    // And now it proceeds, because the evidence is gone.
    $upgrade()->apply();

    expect(true)->toBeTrue();
});

/* ---- the ordering hazard ------------------------------------------------ */

it('counts a cascading delivery row before the parent sweep destroys it', function (string $kind): void {
    /*
     * Both outboxes cascade on their parent, so a parent sweep running first takes the delivery rows
     * with it and the figures an operator reads are zero -- silently, because nothing notices a
     * count that was never taken. Measured: deleting parents first and returning the health code
     * with zero counts satisfied the earlier form of this test completely.
     *
     * Parent and child share one deadline, which is what issuance actually gives them. An earlier
     * form seeded an UNEXPIRED child under an expired parent, which required counting a row the
     * ratified OTP reclaimer would not select -- a second policy smuggled in by a fixture.
     */
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];
    $column = (string) $shape['parentColumn'];
    $deadline = ceremonyPast();
    $parent = seedCeremony($kind, $deadline);

    seedOutbox($outbox, $column, $parent, $deadline, OtpOutboxStatus::Pending);
    seedOutbox($outbox, $column, $parent, $deadline, OtpOutboxStatus::Delivered);

    expect(prune())->toBe(CommandExit::DeliveryHealth->value);

    $output = Artisan::output();

    /*
     * The signal must fire, which is what a cascade-first reclaimer cannot do: with the rows already
     * gone there is nothing left to classify, so it reports nothing undelivered and exits clean. The
     * figures are prose and are not asserted -- see the health case above.
     */
    expect($output)->toContain('undelivered');
    expect($output)->toContain($kind === 'verification' ? 'verification' : 'recovery');
    expect(DB::table($outbox)->count())->toBe(0);
    expect(DB::table($shape['parent'])->count())->toBe(0);
})->with(['verification', 'proof']);

/* ---- the manifest ------------------------------------------------------- */

it('declares all five tables pruned rather than unreclaimed', function (string $table): void {
    /*
     * The manifest is the artefact that found these, and a reclaimer that did not move the
     * declaration would leave the guard reporting a table as unreclaimed while it is being
     * reclaimed -- worse than the original gap, because the next reader would believe it.
     */
    expect(RetentionManifest::pruned())->toHaveKey($table);
    expect(RetentionManifest::unreclaimed())->not->toHaveKey($table);
})->with([
    'auth_identifier_verification_outbox',
    'auth_recovery_proof_outbox',
    'auth_identifier_verifications',
    'auth_recovery_proofs',
    'auth_link_requests',
]);

it('leaves the anchor table still unreclaimed', function (): void {
    /*
     * The control that the implementation moved five declarations rather than emptying the list.
     * `auth_throttle_ip_windows` is #16 -- a mutex anchor needing a capacity decision, not a prune.
     *
     * Asserted as "still present" rather than as the exact remaining set, which would couple these
     * two issues to every future retention decision.
     */
    expect(RetentionManifest::unreclaimed())->toHaveKey('auth_throttle_ip_windows');
});

/* ---- the predicate itself, which three mutants walked through ----------- */

/*
 * NOT ASSERTED, and stated rather than left as a gap: whether the predicate is `<=` or `<` at EXACT
 * equality with the database clock.
 *
 * An earlier version of this file tried. It read the database clock in PHP, seeded a row at that
 * instant, and then let the command read the clock again -- so if a second elapsed between the two
 * reads the row was strictly in the past and a `<` implementation passed. Seeding through
 * shiftDeadlineOnDatabaseClock() moves the read into SQL and does not fix it: the command still
 * reads the clock afterwards.
 *
 * Making it deterministic needs the clock frozen, which is #97's machinery and engine-specific.
 * A racy assertion would be worse than this paragraph: it would pass almost always, fail
 * occasionally on CI for a correct implementation, and teach everyone to re-run the suite. Every
 * reclaimer in the command is already `<=`, and the one-second window this leaves unpinned reclaims
 * a row one sweep later.
 */

it('reads the deadline from the database clock, not the application clock', function (): void {
    /*
     * Measured: a mutant comparing against the APPLICATION clock passed every case, because the two
     * agree in a test. Carbon is pushed two hours behind, so a row the database considers expired is
     * still in the future to PHP and must be reclaimed anyway. #44 put these deadlines on the
     * database clock exactly so a skewed app server cannot extend a security window.
     */
    seedVerification(ceremonyPast(60));

    Carbon::setTestNow(Carbon::instance(app(DatabaseTime::class)->current())->subHours(2));

    try {
        prune();
    } finally {
        Carbon::setTestNow();
    }

    expect(DB::table('auth_identifier_verifications')->count())->toBe(0);
});

it('reclaims an expired row whatever terminal state it reached, and leaves a live one', function (string $kind, string $column): void {
    /*
     * The predicate is expiry, not a terminal state: a consumed row is still the replay defence for
     * its own code until it expires, and auth_attempts sets that precedent. Measured, a mutant
     * deleting on the terminal state instead passed everything, because no fixture populated one.
     */
    seedCeremony($kind, ceremonyPast(), [$column => ceremonyPast(120)]);
    $live = seedCeremony($kind, ceremonyFuture(), [$column => ceremonyPast(120)]);
    $table = ceremonyShape($kind)['parent'];

    expect(DB::table($table)->count())->toBe(2);

    prune();

    // The terminal-but-live row survives: reaching a terminal state is not what reclaims a row.
    expect(DB::table($table)->pluck('id')->all())->toBe([$live]);
})->with([
    'consumed verification' => ['verification', 'consumed_at'],
    'burned verification' => ['verification', 'burned_at'],
    'superseded verification' => ['verification', 'superseded_at'],
    'consumed proof' => ['proof', 'consumed_at'],
    'burned proof' => ['proof', 'burned_at'],
]);
