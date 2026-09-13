<?php

declare(strict_types=1);

use Fissible\Vouch\Contracts\DeliveryEconomics;
use Fissible\Vouch\Contracts\OtpDelivery;
use Fissible\Vouch\Models\AuthIdentifier;
use Fissible\Vouch\Recovery\CredentialRecovery;
use Fissible\Vouch\Recovery\CredentialRecoveryRequest;
use Fissible\Vouch\Tests\Support\ArrayOtpDelivery;
use Fissible\Vouch\Tests\Support\PermittingDeliveryEconomics;
use Illuminate\Foundation\Testing\DatabaseMigrations;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

/*
 * DatabaseMigrations, NOT RefreshDatabase -- the same reason as the other
 * contention suites. RefreshDatabase wraps each test in a transaction on the
 * default connection, so a second connection cannot see its uncommitted rows
 * and every "racing" writer would operate on an empty table. Both assertions
 * here would then pass without anything having raced.
 */
uses(DatabaseMigrations::class);

beforeEach(function (): void {
    $default = Config::string('database.default');
    $settings = Config::array('database.connections.' . $default);

    foreach (['issue_a', 'issue_b'] as $name) {
        config(['database.connections.' . $name => $settings]);
    }

    if ((getenv('VOUCH_TEST_DB') ?: 'sqlite') === 'sqlite'
        && (getenv('VOUCH_SQLITE_PATH') ?: ':memory:') === ':memory:') {
        $this->markTestSkipped(
            'Contention tests need a shared database. In-memory SQLite gives each connection '
            . 'its own, so these would pass without racing. Set VOUCH_SQLITE_PATH to a file, '
            . 'as the CI matrix does.',
        );
    }
});

function contendedRecoveryRequest(): CredentialRecoveryRequest
{
    return new CredentialRecoveryRequest(
        type: 'email',
        submittedIdentifier: 'ada@acme.example',
        tenantId: null,
        clientIp: '203.0.113.10',
    );
}

function contendedAccount(): void
{
    AuthIdentifier::create([
        'user_id' => 1,
        'type' => 'email',
        'value' => 'ada@acme.example',
        'verified_at' => now(),
    ]);

    app(\Fissible\Vouch\Factors\Drivers\PasswordFactor::class)->enroll(1, ['password' => 'old-password']);
}

/**
 * Rows that could still be redeemed: unconsumed, unsuperseded, unexpired.
 *
 * The column check is not defensive noise. SQLite resolves a double-quoted
 * identifier it does not recognise as a STRING LITERAL, so `whereNull` on a
 * missing column matches nothing and silently returns 0 -- a count that reads
 * like "no live proofs" and would let this fixture pass against an
 * implementation that never built the column at all. MySQL and PostgreSQL
 * would error on the same query, so the vacancy is engine-specific too.
 */
function stillRedeemableCount(): int
{
    foreach (['consumed_at', 'superseded_at'] as $column) {
        if (! Schema::hasColumn('auth_recovery_proofs', $column)) {
            throw new RuntimeException(
                "auth proofs have no {$column} column, so this count cannot mean what it says.",
            );
        }
    }

    return DB::table('auth_recovery_proofs')
        ->whereNull('consumed_at')
        ->whereNull('superseded_at')
        ->whereRaw('expires_at > CURRENT_TIMESTAMP')
        ->count();
}

it('leaves exactly one live proof when two issuances interleave', function (): void {
    /*
     * A genuine interleave rather than two sequential calls.
     *
     * Connection A opens a transaction and issues, holding whatever lock the
     * implementation takes; B then issues for the same identifier. Sequential
     * issuance already supersedes correctly -- the second reads the first's
     * committed row -- so only an interleave can show whether supersession
     * SERIALIZES. If both requests read "no prior live proof" before either
     * writes, each creates a proof and supersedes nothing, and the user is back
     * to two usable password-reset capabilities: the exact defect, reachable by
     * double-clicking a resend button.
     *
     * The invariant does not name a mechanism. Whether B blocks and then
     * supersedes, or fails to acquire and refuses, one live proof is the only
     * acceptable end state.
     */
    contendedAccount();

    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    $a = DB::connection('issue_a');
    $a->beginTransaction();

    try {
        app(CredentialRecovery::class)->request(contendedRecoveryRequest());

        try {
            app(CredentialRecovery::class)->request(contendedRecoveryRequest());
        } catch (Throwable) {
            // A refusal to race is an acceptable outcome; an extra live proof
            // is not. The assertions below judge the end state, not the path.
        }
    } finally {
        $a->commit();
    }

    expect(stillRedeemableCount())->toBe(1);
});

it('leaves exactly one live proof across repeated rapid issuance', function (): void {
    /*
     * The resend-button case, stated plainly: however many times a user asks
     * for another code, they hold exactly one that works. Every earlier proof
     * must be superseded rather than merely out-sorted, so this also fails
     * against an implementation that retires only the immediately preceding one.
     */
    contendedAccount();

    app()->instance(OtpDelivery::class, new ArrayOtpDelivery());
    app()->instance(DeliveryEconomics::class, new PermittingDeliveryEconomics());

    foreach (range(1, 5) as $ignored) {
        app(CredentialRecovery::class)->request(contendedRecoveryRequest());
    }

    expect(DB::table('auth_recovery_proofs')->count())->toBe(5)
        ->and(stillRedeemableCount())->toBe(1);
});
