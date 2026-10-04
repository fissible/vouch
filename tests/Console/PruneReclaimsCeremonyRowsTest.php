<?php

declare(strict_types=1);

use Fissible\Vouch\Console\CommandExit;
use Fissible\Vouch\Console\RetentionManifest;
use Fissible\Vouch\Notifications\OtpOutboxStatus;
use Fissible\Vouch\Support\DatabaseTime;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Artisan;
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

function seedVerification(string $expiresAt, string $value = 'ada@example.test'): int
{
    return (int) DB::table('auth_identifier_verifications')->insertGetId([
        'identifier_type' => 'email',
        'identifier_value' => $value,
        'code_hash' => str_repeat('a', 64),
        'is_decoy' => 0,
        'attempts' => 0,
        'expires_at' => $expiresAt,
        'created_at' => $expiresAt,
        'updated_at' => $expiresAt,
    ]);
}

function seedRecoveryProof(string $expiresAt, string $value = 'ada@example.test'): int
{
    return (int) DB::table('auth_recovery_proofs')->insertGetId([
        'identifier_type' => 'email',
        'identifier_value' => $value,
        'code_hash' => str_repeat('b', 64),
        'is_decoy' => 0,
        'attempts' => 0,
        'expires_at' => $expiresAt,
        'created_at' => $expiresAt,
        'updated_at' => $expiresAt,
    ]);
}

function seedOutbox(string $table, string $parentColumn, int $parentId, string $expiresAt, OtpOutboxStatus $status): int
{
    return (int) DB::table($table)->insertGetId([
        'opaque_id' => bin2hex(random_bytes(32)),
        $parentColumn => $parentId,
        'payload' => null,
        'status' => $status->value,
        'expires_at' => $expiresAt,
        'created_at' => $expiresAt,
        'updated_at' => $expiresAt,
    ]);
}

/** A link request, with the federated identity it points at -- which must OUTLIVE it. */
function seedLinkRequest(string $expiresAt): int
{
    $connection = (int) DB::table('auth_connections')->insertGetId([
        'trust_email_verified' => 0,
        'auto_link' => 0,
        'created_at' => $expiresAt,
        'updated_at' => $expiresAt,
    ]);

    $identity = (int) DB::table('auth_federated_identities')->insertGetId([
        'connection_id' => $connection,
        'issuer' => 'https://issuer.example.test',
        'subject' => 'subject-1',
        'created_at' => $expiresAt,
        'updated_at' => $expiresAt,
    ]);

    return (int) DB::table('auth_link_requests')->insertGetId([
        'user_id' => 7,
        'federated_identity_id' => $identity,
        'expires_at' => $expiresAt,
        'created_at' => $expiresAt,
        'updated_at' => $expiresAt,
    ]);
}

/**
 * The three ceremony kinds, each as the pieces every case needs.
 *
 * One match rather than three strings threaded through a dataset: a dataset of callables is not
 * provably callable at level 9, and a dataset of table names had the test re-deriving which parent
 * went with which outbox.
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

function seedCeremony(string $kind, string $expiresAt): int
{
    return match ($kind) {
        'verification' => seedVerification($expiresAt),
        'proof' => seedRecoveryProof($expiresAt),
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

it('leaves a delivery row that has not expired', function (string $kind): void {
    // The non-vacuity control for every deletion above: a sweep that emptied the table would pass
    // all of them.
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];

    seedOutbox($outbox, (string) $shape['parentColumn'], seedCeremony($kind, ceremonyFuture()), ceremonyFuture(), OtpOutboxStatus::Pending);

    prune();

    expect(DB::table($outbox)->count())->toBe(1);
})->with(['verification', 'proof']);

it('reports an expired undelivered row from either outbox as delivery health', function (string $kind): void {
    /*
     * The operational signal, not just the deletion. An expired-undelivered OTP row already sets a
     * distinct exit code and warns, because it means a delivery worker stopped doing its job. A
     * recovery proof or an identifier verification that expired undelivered says exactly the same
     * thing, so it has to reach the same signal rather than being swept quietly.
     */
    $shape = ceremonyShape($kind);

    seedOutbox((string) $shape['outbox'], (string) $shape['parentColumn'], seedCeremony($kind, ceremonyFuture()), ceremonyPast(), OtpOutboxStatus::Pending);

    expect(prune())->toBe(CommandExit::DeliveryHealth->value);
    expect(Artisan::output())->toContain('undelivered');
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
     * both of which are separately declared retained. If reclaiming the ceremony took the outcome
     * with it, the decision would be wrong and this is what would say so.
     */
    $verifiedAt = ceremonyPast();

    DB::table('auth_identifiers')->insert([
        'user_id' => 7,
        'type' => 'email',
        'value' => 'ada@example.test',
        'verified_at' => $verifiedAt,
        'is_primary' => 1,
        'created_at' => $verifiedAt,
        'updated_at' => $verifiedAt,
    ]);

    seedVerification(ceremonyPast());
    seedLinkRequest(ceremonyPast());

    prune();

    expect(DB::table('auth_identifier_verifications')->count())->toBe(0);
    expect(DB::table('auth_link_requests')->count())->toBe(0);

    // The outcomes, untouched.
    expect(DB::table('auth_identifiers')->whereNotNull('verified_at')->count())->toBe(1);
    expect(DB::table('auth_federated_identities')->count())->toBe(1);
});

/* ---- the ordering hazard ------------------------------------------------ */

it('counts a cascading delivery row before the parent sweep destroys it', function (string $kind): void {
    /*
     * Both outboxes cascade on their parent, so a parent sweep that ran first would take the
     * delivery rows with it and the figures an operator reads would be zero -- silently, because
     * nothing else notices a count that was never taken.
     *
     * The row here is NOT expired on its own; only its parent is. So it can only be accounted for
     * by classifying before the cascade, which is how the existing OTP reclaimer orders itself
     * against `auth_attempts`.
     */
    $shape = ceremonyShape($kind);
    $outbox = (string) $shape['outbox'];

    seedOutbox($outbox, (string) $shape['parentColumn'], seedCeremony($kind, ceremonyPast()), ceremonyFuture(), OtpOutboxStatus::Pending);

    expect(prune())->toBe(CommandExit::DeliveryHealth->value);

    // Reported, and gone: a report that counted it while leaving it behind would be the other bug.
    expect(Artisan::output())->toContain('undelivered');
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

it('leaves exactly the anchor table still unreclaimed', function (): void {
    /*
     * The control that the implementation moved five declarations rather than emptying the list.
     * `auth_throttle_ip_windows` is #16 -- a mutex anchor needing a capacity decision, not a prune --
     * and it is the only entry that should remain.
     */
    expect(array_keys(RetentionManifest::unreclaimed()))->toBe(['auth_throttle_ip_windows']);
});
