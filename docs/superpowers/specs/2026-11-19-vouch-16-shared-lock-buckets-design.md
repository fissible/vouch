# #16 — shared lock buckets, rotation overlap, and IP-window reclamation

Decided 2026-11-19 (issue #16, maintainer comment).

## Problem

`auth_throttle_ip_windows` is three things at once: per-IP window state, the FK
parent of `auth_throttle_tuples`, and the mutex that serializes one IP's
read-check-write. Because it is the mutex, nothing deletes it, so it grows with
every distinct client IP and keeps each IP digest forever. A scanner drives that
growth for free.

#46 solved the same shape for issuance with a fixed, keyed bucket table. Its
secret can only be rotated with a coordinated deploy, because old and new
processes derive different buckets mid-rollout.

## Design

**One derivation.** `LockBucket` owns the keyed mapping for every bucketed mutex:
`HMAC(secret, domain ‖ segments) mod 4096`, byte-identical to #46's for the
`issuance.mutex` domain. Domains are separated by the label inside the message,
not by deriving per-domain keys, so an existing install's issuance mapping does
not move on upgrade.

**One secret.** `vouch.lock_buckets.secret` (`VOUCH_LOCK_BUCKETS_SECRET`). When it
is unset, the legacy `vouch.issuance_locks.secret` / `VOUCH_ISSUANCE_LOCKS_SECRET`
is used, so existing installs need no change. The new key wins when both are set.

**Rotation overlap.** `vouch.lock_buckets.previous_secret`
(`VOUCH_LOCK_BUCKETS_PREVIOUS_SECRET`). While it is set, every bucketed lock takes
the bucket under each secret, deduplicated, in ascending bucket order. Rotation:

1. Deploy with the new secret as current and the old one as previous. A process
   still on the old config locks only the old bucket, and every updated process
   locks it too, so serialization holds throughout the rollout.
2. Once every process runs the step-1 config, deploy again without the previous
   secret. Updated processes all hold the new bucket.

Ascending order means no two updated processes can deadlock. A process on the old
config takes one bucket, so it waits on nothing else in that domain.
`vouch:doctor` reports a `rotating` row while a previous secret is set.

**IP windows.** A new `auth_throttle_ip_locks` table holds 4096 seeded buckets in
the `throttle.ip` domain, keyed by dimension and IP digest. `recordIpFailure` takes
the IP's bucket first, then runs the existing parent logic unchanged. It still locks
the parent row, so a process on the previous release still serializes with an
updated one on the parent row during a rolling deploy.

The bucket lock is the first statement on MySQL and PostgreSQL. It is a locking
read, so it opens no InnoDB snapshot and the tuple count still sees committed
markers. On SQLite the database write lock is the mutex, so the existing leading
write stays first and the bucket read follows it. A leading read there would turn
concurrent writers into immediate `SQLITE_BUSY` on lock upgrade.

`vouch:prune` reclaims expired IP windows after its main transaction, one window
per short transaction: lock the window's buckets, then delete the row only if the
same database-clock expiry predicate `ipState` uses still holds. Tuples cascade. A
window renewed while prune waited survives the recheck. SQLite skips the bucket
read for the same upgrade reason.

## Costs

- False sharing: unrelated IPs in one bucket serialize for one throttle
  transaction. State never crosses between them. A bucket wait counts against the
  existing bounded lock wait, whose contention outcome is `skipped`.
- During a rotation overlap each lock takes two buckets, roughly doubling false
  sharing until the second deploy.
- Rotation still needs the operator to finish step 2. Vouch cannot observe a
  rollout, so doctor flags the overlap rather than ending it.

## Out of scope

#17 (`auth_subject_locks`) moves onto the same derivation in its own change.
