# Vouch operations

## Upgrading to per-session records (#30)

Deploy this upgrade with host traffic paused. Publish and run the new
`2026_09_13_000002_revoke_legacy_auth_sessions.php` migration, flush all existing
host sessions using the host session backend's invalidation procedure, and
restart long-running application workers before resuming traffic. Users must
sign in again.

The migration revokes existing live Vouch rows and preserves their bindings so
`ValidatesVouchSession` refuses surviving unmarked sessions. It does not alter the
schema or restore revoked sessions on rollback. The host session flush is also
required: the old per-user upsert may already have rebound a device's row away.
That device has neither an ownership marker nor a matching row and cannot be
distinguished from a host session Vouch never established.

New logins persist one row per session and an ownership marker that remains
valid through the host guard's session rotation. Re-authentication supersedes
only that device's previous row. Keep `ValidatesVouchSession` on authenticated
host routes so missing, mismatched, or revoked records destroy owned sessions.
Live unmarked recovery-grace sessions continue to pass this middleware.

## Supported database engines

MySQL 8.0 or later, PostgreSQL, and SQLite. Nothing else.

That set is not a preference. It is the set the suite runs against on every
change, and every engine-specific fragment Vouch emits — interval arithmetic, the
deadline predicates, identifier collations, identifier quoting — is written for
exactly those three. An unrecognised driver is REFUSED by name rather than sent
down whichever branch happens to be last: falling back would put untested SQL
into a security comparison, on whichever engine nobody had tried.

MariaDB is included in that refusal, deliberately. It once shared MySQL's
interval arm, which read as support without being it — Laravel reports it as its
own driver name, so that arm was reachable, while the identifier-collation
migration would have handed it PostgreSQL syntax and no MariaDB host could have
finished migrating. Its interval syntax genuinely is MySQL's; what it lacks is
every other engine-specific branch, a CI leg, and anyone ever having run the
suite against it. Supporting it is a decision with a test matrix attached, not a
missing match arm.

## Upgrading to deterministic identifier equality (#59)

Publish and run `2026_09_25_000001_deterministic_identifier_equality.php` with
host traffic paused. It installs a deterministic collation on every column that
holds an identifier value or type, in `auth_identifiers`,
`auth_identifier_verifications` and `auth_recovery_proofs`, and rewrites existing
rows into the canonical form `IdentifierCanonicalizer` produces.

The supported collations are part of the contract from here on:
`utf8mb4_0900_bin` on MySQL, `C` on PostgreSQL, and SQLite's byte-comparing
default. Identifier equality is then Vouch's decision rather than the engine's,
so two spellings are one identifier exactly when they canonicalize alike, and
the unique indexes over those columns mean the same thing on every engine.
Leave the collations as the migration sets them. Moving a column back to a
case- or accent-insensitive collation restores the behavior this upgrade
removes, and does so silently.

The migration reads every identifier table and decides the whole upgrade before
it writes anything, so a refusal changes neither rows nor schema and it is safe
to reconcile what it reports and run it again. That read-then-write shape is also
why traffic must be paused: a row written between the two is not seen by the
collision check, even though the rewrite does reach it. Canonicalizing such a row
can collide with a surviving one and fail the migration on the deterministic
unique index — and because the upgrade is not wrapped in a transaction, the
collation change, the deletions and the rewrites already applied stay applied.

Deciding first no longer means holding every identifier row in memory. The scan
streams each table through a temporary working table, asks the engine which
groups have more than one spelling in them, and reads back only those rows, so
peak memory tracks the page size rather than the installation. The rewrite is
bounded the same way: it recomputes each page's canonical spellings from the rows
themselves rather than accumulating one pair per distinct spelling, which on a
host whose identifiers are all non-canonical was one pair per row. Measured flat
at roughly 6 MB from a thousand rows to four hundred thousand, whether or not the
identifiers need rewriting — that last clause is new, and before it the same
figure held only for a table already canonical. No `memory_limit` change is
needed for the run.

Plan the window on time rather than on memory. The rewrite matches rows by
spelling, which the deterministic unique index on `(type, value)` cannot serve
from the value alone, so the work per page grows with the table: measured on
SQLite, 100 000 non-canonical rows took about 24 seconds and 400 000 took about
four minutes. Four times the rows, ten times the time. Memory is flat; the
duration is not.

One outcome needs no decision from the operator. A collision between live
recovery proofs or identifier verifications deletes every row in it: those are
minute-scale grants rather than records, and the cost is one re-request.

The migration refuses, with `IdentifierCollisionsFound`, when a collision reaches
an `auth_identifiers` row or a consumed or burned proof. The exception carries
every colliding group found across every table: the table, the canonical value
contended for, and the row ids. One run therefore reports everything that needs
attention rather than the first thing it met. Reconciling means deciding which
row keeps the address and removing or re-pointing the others. The package cannot
choose: an account row is an identity claim, and a consumed or burned proof is
the record that a redemption or an exhausted guessing budget happened.

Rollback is deliberately empty. Case folding and normalization have no inverse,
and restoring a looser collation can violate the unique indexes outright, because
rows that only byte equality keeps apart are exactly what an accent-insensitive
index rejects. A rolled-back host loses nothing by keeping the deterministic
collation: canonical rows compare identically under either.

## Upgrading to a collation that pads nothing (#63)

Publish and run `2026_09_25_000002_identifier_collation_without_padding.php`. It
concerns MySQL only, and only an installation that ran
`2026_09_25_000001_deterministic_identifier_equality.php` before this release.
That migration installed `utf8mb4_bin`, which is deterministic and PAD SPACE
both: MySQL matched a stored `ada@acme.example` for a query of
`ada@acme.example ` and rejected the padded spelling as a duplicate under
`unique(type, value)`, where PostgreSQL's `C` and SQLite's byte comparison do
neither. `IdentifierCanonicalizer` normalizes case and Unicode but does not
trim, so the space reaches both the stored value and the lookup parameter and
the engine decided. This migration moves the six identifier columns to
`utf8mb4_0900_bin`, which is NO PAD.

It rewrites no rows, is safe to run twice, and does nothing on PostgreSQL or
SQLite. A fresh installation needs it for nothing: the conversion migration now
installs `utf8mb4_0900_bin` itself, so no installation holds a padding collation
even briefly. Whether a trailing space ought to be trimmed is a separate
question about what an identifier is, and is deliberately left alone — what this
settles is that the answer no longer depends on which database is installed.

**MySQL 8.0 is this package's minimum from this release on.** `utf8mb4_0900_bin`
is the only binary utf8mb4 collation MySQL offers that is NO PAD, and it exists
from 8.0 only; 5.7 has `utf8mb4_bin` and nothing there behaves like PostgreSQL's
`C` for trailing whitespace. PostgreSQL and SQLite gain no new requirement.

MySQL refuses to change the collation of a column that participates in a foreign
key, with `3780 Referencing column ... in foreign key constraint`. No shipped
constraint references any of the six columns, so this reaches only a host that
added one of its own — and it fails at migrate time rather than converting part
of the schema. Drop that constraint, run the migration, and recreate it.

Rollback is deliberately empty, and for a stronger reason than the conversion's:
tightening back to `utf8mb4_bin` fails outright on the installations that most
needed this. Under PAD SPACE `ada@acme.example` and `ada@acme.example ` are one
value, so `unique(type, value)` rejects the change with `1062 Duplicate entry` on
any host that has stored both spellings since. A rolled-back host keeps the NO
PAD collation and loses nothing: values carrying no trailing whitespace compare
identically under either.

## Upgrading to a bucketed issuance mutex (#46)

Set `VOUCH_ISSUANCE_LOCKS_SECRET` before deploying, then publish and run
`2026_09_26_000001_bucketed_issuance_locks.php`.

The issuance mutex used to hold one row per submitted identifier, allocated
before resolution and whether or not resolution succeeded. The table therefore
grew with attacker-chosen input — the per-identifier issuance throttles count
repetition, and rotating identifiers walks past them — and it retained each
submitted string verbatim and permanently, addresses of people who are not users
included, with no reclamation path. It now holds a fixed 4,096 rows keyed only by
a bucket number, and issuance locks
`HMAC(secret, ceremony ‖ type ‖ canonical identifier) mod 4096`. The table is a
fixed size forever and retains no identifier, so there is nothing to reclaim.

The migration discards every existing row rather than converting it: a mutex is
not a record of anything, and those rows are exactly the strings this change
stops retaining. Rollback is deliberately empty — it would mean inventing them
again. Run it with issuance traffic paused, because the table is dropped and
recreated.

**The secret has no shipped default and the package refuses to boot without one.**
A default would give every installation the same publicly derivable mapping from
identifier to mutex row, and an attacker who worked it out once could aim
submissions at any victim's mutex on any host. Use at least 32 bytes of random
data. `vouch:doctor` still runs when it is missing, so the command whose job is to
report what is unconfigured is not the command a missing secret stops.

It is dedicated rather than derived from `APP_KEY` on purpose. Rotating `APP_KEY`
invalidates sessions and attempts and is expected to be survivable, and it must
not also remap every mutex. **Rotating this secret needs a coordinated
deployment**: it moves every bucket at once, so mid-rotation old and new processes
derive different mutexes for one identifier and stop serializing it for as long
as the rollout takes.

Two unrelated identifiers may now land in one bucket and serialize against each
other for the length of one issuance transaction. That is a latency cost and
nothing else: no state crosses between them, and with ten simultaneous distinct
issuances an arriving request contends roughly once in 455.

## Moving MySQL dates past 2038

Publish and run `2026_10_03_000001_date_columns_beyond_2038.php` with host traffic
paused. It converts every remaining `TIMESTAMP` column in Vouch's `auth_` table
namespace to `DATETIME`, preserving precision, nullability and indexes. The
underscore is literal, so a host's `authentication_events` is outside that
namespace. Fresh installations already create `DATETIME` columns; PostgreSQL
and SQLite already store dates beyond 2038 and the upgrade changes neither.

**The migration and runtime connections must use UTC.** Set
`'timezone' => '+00:00'` on the relevant MySQL connection in
`config/database.php`, rebuild the host's cached configuration, and restart
workers and other long-lived processes so their connections pick it up. Check
`SELECT @@session.time_zone, @@system_time_zone` on that connection: an explicit
`+00:00`, `UTC` or `Etc/UTC` is accepted, as is `SYSTEM` when the system zone is
UTC. Every other zone is refused before any schema change. A zero offset today
does not establish UTC across daylight-saving transitions.

If the host currently uses another zone, coordinate the connection change and
the migration in the same maintenance window, with both requests and workers
paused. Audit any host code that treats database literals as local time before
resuming traffic. `TIMESTAMP` renders an instant in the connection's zone;
`DATETIME` stores that rendering without conversion. Running the conversion in
UTC preserves the epoch of every stored instant. Silently forcing UTC only for
the migration would leave a +02:00 runtime reading existing windows two hours
earlier. Keeping the ambient zone is unsafe too: measured in Europe/Berlin, two
instants an hour apart both became 02:30 at the autumn transition. The upgrade
refuses rather than choosing either failure for the operator.

MySQL rebuilds each affected table with `ALGORITHM=COPY`. There is one `ALTER`
per table, covering all its date columns, and writes are blocked for the
duration. An open read transaction can hold a metadata lock and make the
upgrade fail with error 1205; drain those transactions as well as writers and
plan the maintenance window for the largest tables. Progress is per-table,
**not atomic across tables**. If a later table fails, earlier conversions stay
applied. Resolve the lock or other reported failure and rerun: columns already
converted are left alone.

The host's Sanctum `personal_access_tokens` table has the same `TIMESTAMP`
ceiling and is the host's responsibility to convert under the same UTC
contract. Vouch must not alter a table it does not own. Until that table is
converted too, widening Vouch's token-assurance dates alone does not make token
issuance work beyond 2038.

Rollback is deliberately empty. Narrowing a column back to `TIMESTAMP` fails
on any installation that has since stored a post-2038 value, and retaining
`DATETIME` loses nothing.

## Refusing an identifier that cannot be stored (#64, #65)

A submitted identifier is now refused at the boundary instead of being passed to a
column that would silently alter it. Two exceptions reach a host, both unchecked,
and **a host that builds its own forms must catch them**:

| Exception | When |
|---|---|
| `Fissible\Vouch\Identifiers\MalformedIdentifier` | The submitted type or value is not valid UTF-8, or contains a C0 control or DELETE. Its `reason` is `InvalidEncoding` or `ForbiddenCharacter`, so a form can say which. |
| `Fissible\Vouch\Persistence\ValueBoundViolation` | The canonical form is longer than the column it lands in — 255 characters for an identifier value, 32 for a type. |

Both come out of constructing `CredentialRecoveryRequest`,
`IdentifierVerificationRequest` or `FirstCredentialRequest`, or out of writing an
`AuthIdentifier`; the length one also comes out of `CredentialRecovery::request()`
and `IdentifierVerifier::request()`, which write the proof row. `AuthFlow::advance()`
raises neither: the identify step renders its own refused screen for both and
leaves `auth_attempts.identifier` null.

Neither is repaired, and that is the point. Stripping a NUL or truncating a tail is
how an attacker-chosen string reaches somebody else's identifier: PostgreSQL
truncates text at a NUL, and MySQL without a strict `sql_mode` truncates an
over-long value and then matches the next distinct identifier to that truncation
under `unique(type, value)`. Trailing whitespace is deliberately **not** refused —
a padded spelling is a different identifier, not an invalid one.

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
| `durable_queue` | Configure the `OtpDelivery` to use a durable asynchronous queue connection and run its worker. This is separate from binding the delivery implementation; a bound provider on `QUEUE_CONNECTION=sync` is still rejected. |
| `DeliveryEconomics` | Bind a real `DeliveryEconomics` implementation. |
| `CaptchaVerifier` | Only when `vouch.throttle.captcha.enabled` is true, bind a real `CaptchaVerifier` implementation. |
| `vouch.attempts.ttl_seconds` | Set `VOUCH_ATTEMPT_TTL` to a positive whole number of seconds, or leave it unset for the shipped 600. A blank value casts to zero, and an edited config that drops the `(int)` cast yields the string `"600"`; both are rejected, and both otherwise fail every login at request time. |
| `vouch.issuance_locks.secret` | Set `VOUCH_ISSUANCE_LOCKS_SECRET` to at least 32 bytes of dedicated random material — not `APP_KEY`, whose rotation must stay survivable. The package ships no default, because a shared one would give every installation the same derivable bucket mapping. |
| `vouch.declared_abilities` | Only when `vouch.assurance_strict` is true, list every ability named as a key in `vouch.assurance_requirements`. An undeclared mapped ability is usually a typo, which leaves the intended policy unreachable. |

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
