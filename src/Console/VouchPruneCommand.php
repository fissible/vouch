<?php

declare(strict_types=1);

namespace Fissible\Vouch\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;

/**
 * Housekeeping only.
 *
 * This command reaps dead rows. It is never the enforcement mechanism for any
 * expiry: attempt expiry is enforced in the store's guarded UPDATE predicates,
 * and recovery-grace expiry is enforced per-request on every vouch-owned route.
 *
 * In particular it does NOT delete sessions whose recovery grace has lapsed.
 * Doing so would turn a rejected grace session into an anonymous one for any
 * request arriving before the sweep, making the sweep the enforcement it must
 * never be.
 */
final class VouchPruneCommand extends Command
{
    protected $signature = 'vouch:prune';

    protected $description = 'Delete expired attempts and long-revoked sessions.';

    public function handle(): int
    {
        /*
         * Query-builder deletes rather than Eloquent's: Eloquent\Builder::delete()
         * is declared mixed, and a sweep has no use for model events anyway.
         * Challenges are removed by the cascadeOnDelete() on
         * auth_challenges.attempt_id, so they need no separate pass.
         */
        $attempts = DB::table('auth_attempts')
            ->where('expires_at', '<=', now())
            ->delete();

        $retentionDays = Config::integer('vouch.sessions.revocation_retention_days', 30);

        $sessions = DB::table('auth_sessions')
            ->whereNotNull('revoked_at')
            ->where('revoked_at', '<=', now()->subDays($retentionDays))
            ->delete();

        $this->info(sprintf('Pruned %d attempt(s) and %d revoked session(s).', $attempts, $sessions));

        return self::SUCCESS;
    }
}
