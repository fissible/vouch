# Vouch operations

## Login adoption prerequisites

An unverified identifier is invisible to login by design. Its refusal is deliberately
indistinguishable from a wrong identifier, so a login endpoint cannot disclose whether
an identifier exists or is awaiting verification.

Before enabling login, establish these prerequisites in order. Run
`php artisan vouch:doctor` to check the complete staircase together; it reports
aggregate readiness only and never accepts an identifier argument.

| Prerequisite | Host responsibility |
|---|---|
| `verified_at` | Use the identifier verification ceremony (`IdentifierVerifier`) to prove control of the identifier and establish `verified_at`. Do not set it merely because the host has collected an identifier value. |
| `OtpDelivery` | Bind a real `OtpDelivery` implementation that can deliver OTPs. |
| Durable asynchronous queue | Configure the `OtpDelivery` to use a durable asynchronous queue connection and run its worker. This is separate from binding the delivery implementation; a bound provider on `QUEUE_CONNECTION=sync` is still rejected. |
| `DeliveryEconomics` | Bind a real `DeliveryEconomics` implementation. |
| `CaptchaVerifier` | Only when `vouch.throttle.captcha.enabled` is true, bind a real `CaptchaVerifier` implementation. |

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

## Token issuance audit

Run `php artisan vouch:audit-tokens` after introducing Vouch token issuance and
again when a host changes authentication or route composition. It has two
different evidence sources: PHP's built-in lexer scans the configured
`vouch.audit.paths` roots (default `app`, `routes`) for direct `createToken()`
calls, while the live router supplies already-expanded middleware coverage. The
command names dynamic issuance-shaped calls and paths it cannot read instead of
claiming a clean scan it could not perform. Use `--json` for automation.

The default is report-only. `--strict` is intentionally noisy and therefore is
not a default CI gate: it fails on unallowlisted direct sites, unknown source
seams, and malformed or stale allowlist entries, but never on uncovered routes.
Coverage alone cannot say that an endpoint ought to accept bearer tokens. An
allowlist is an owned decision, not a mute button: every entry needs both a
`rationale` and `owner`, with an optional `reviewed` date.

Sanctum tokens issued outside `Vouch::issueToken` have no assurance evidence.
Observe mode identifies them without stopping traffic; when preparing enforce
mode, drop and recreate those tokens through the Vouch issuer rather than trying
to backfill a human proof that was never recorded. The token gate is scoped to a
token actor, so cookie-authenticated traffic follows session assurance instead.
Machine tokens are explicitly recorded as machine actors, and bearer refusal
uses RFC 9470 only when a human token needs stronger proof; opaque invalid or
machine-on-human-route cases remain RFC 6750 `invalid_token`.

## Authentication-throttle posture

Throttle keys are HMAC digests derived from `APP_KEY`. Rotating that key deliberately
resets every counter and identifier lock because old rows can no longer be addressed.
Unlike session invalidation, that reset briefly restores an attacker's full budget;
plan key rotation as a security-control reset rather than treating it as storage-only
maintenance.

Vouch reads client IP exactly once through Laravel's `Request::ip()` at the HTTP
boundary. The host application's `TrustProxies` configuration therefore owns proxy
trust. With too little trust, many clients may collapse onto one load-balancer or CGNAT
address; with too much, an attacker may forge forwarding headers. IP is advisory:
null skips the dimension, IPv6 is normalized to a /64, and no IP state can create or
present an identifier lock.

IP, tenant, and global dimensions ship in observe mode. Tenant and global enforcement
remain opt-in because a mistaken shared threshold can refuse an entire population.
Use `vouch:throttle:report` to measure aggregate distributions before enabling a shared
limit; do not add candidate lookup or plaintext subject columns to make observation
more convenient.

Identifier locks expire by time and are capped at one hour. Vouch 2.3b deliberately
has no administrative unlock: an unlock is a security-relevant action that requires
Phase 2.4's redacted `AuditSink`. Do not delete lock rows manually or add an unaudited
unlock endpoint; configure a wait-out-able duration until that audited path ships.
