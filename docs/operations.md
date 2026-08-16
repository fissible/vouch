# Vouch operations

## OTP worker and one-minute maintenance

Email and SMS OTP delivery requires a durable asynchronous Laravel queue and a
running worker for the configured `vouch.otp.queue` (default: `vouch-otp`). A
successfully enqueued opaque outbox id is not proof that a worker is consuming it.
Vouch rejects sync, deferred, background, null, and mixed failover queues before
charging issuance or writing challenge state.

Run both outbox redispatch and pruning at least once per minute. The redispatch
command recovers the commit-before-queue-push window. The prune command removes
expired ciphertext and turns expired-undelivered rows into the package's aggregate
dead-worker signal. With the default 120-second OTP TTL and a one-minute sweep, live
ciphertext is retained for at most 180 seconds.

`vouch:prune` has a three-way exit contract:

| Status | Meaning | Owner |
|---:|---|---|
| `0` | Sweep succeeded; no expired-undelivered OTP work was found | Maintenance healthy |
| `1` | The sweep itself failed and its transaction rolled back | Prune/database owner |
| `2` | Sweep and deletions succeeded; expired-undelivered OTP work was found | Queue/delivery-worker owner |

Do **not** use
`Schedule::command('vouch:prune')->onFailure(...)`. Laravel treats every non-zero
status as task failure, which collapses statuses `1` and `2` and sends a successful
sweep to the wrong owner. Preserve the status through a scheduled callback:

```php
use Fissible\Vouch\Console\VouchPruneSchedule;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schedule;

Schedule::command('vouch:otp-outbox:dispatch')
    ->everyMinute()
    ->withoutOverlapping();

Schedule::call(function (): void {
    $status = Artisan::call('vouch:prune');

    VouchPruneSchedule::after(
        $status,
        Artisan::output(),
        static function (string $aggregate): void {
            Log::warning('Vouch found expired undelivered OTP work.', [
                'aggregate' => $aggregate,
            ]);
        },
    );
})->everyMinute()->name('vouch:prune');
```

The callback completes normally for `0` and `2`; it throws for `1` or any unknown
status. Route the status-`2` warning to delivery-worker health, and preserve its
aggregate-only output—do not add identifier, IP, tenant, digest, or candidate lookup.

## Aggregate throttle report

`php artisan vouch:throttle:report` prints active bucket totals, fixed distribution
bands, configured threshold-crossing counts, and current aggregate OTP outbox health.
Use `--json` for machine-readable output.

The report deliberately accepts no subject filter. It cannot look up an identifier,
IP, tenant, digest, or arbitrary candidate and emits no per-bucket row. Subject-level
operability waits for Phase 2.4's redacted, auditable path.
