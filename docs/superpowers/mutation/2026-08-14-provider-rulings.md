# VouchServiceProvider — 62 rows grouped by expression and sink

Grouped by the **exact expression and its dataflow sink**, never by mutator
family. One reviewed expression may discharge several mutation IDs; a mutator
name discharges none.

## A — filesystem path concatenations (15 rows) — NOT prose

Lines 31, 226, 227, 254, 258. Expression shape: `__DIR__ . '/../<path>'`.

| Sink | Effect if broken |
|---|---|
| `mergeConfigFrom` (31) | package config never merges; every `config('vouch.*')` read falls back or fails |
| `loadMigrationsFrom` (226) | schema never ships |
| `loadRoutesFrom` (227) | `/vouch/auth` and the recovery routes do not exist |
| `publishes` config (254) | `vendor:publish` writes nothing |
| `publishes` migrations (258) | host cannot take ownership of the schema |

**These are paths, not messages.** A blanket "Concat is prose" ruling would have
wrongly discharged all fifteen — in this file alone, and silently, because a
package whose routes do not load fails at the host's first request rather than in
this repository's suite.

## B — registration removals (~29 rows) — real

`RemoveMethodCall` on every `bind`/`singleton`/`aliasMiddleware`/
`pushMiddlewareToGroup`/`commands` call, plus `registerFactorDrivers()` at 133.
Sink: the container and the router. Removing any one silently deletes a control
at runtime — the factor registry, the session middleware, the assurance
middleware, the CSPRNG binding. Partially covered already by
`tests/Database/ContainerWiringTest.php`; each remaining ID needs its own
resolution assertion.

## C — the web-group guard (3 rows + 6 message rows)

Lines 240 `IfNegated`/`RemoveNot` and 242 `CoalesceRemoveLeft` are the guard that
refuses to boot when `ValidatesVouchSession` is absent from the `web` group. Real
— it is the control that makes the middleware mandatory rather than advisory.

Line 246 (6 rows) is that guard's `RuntimeException` message. Dataflow: thrown,
developer-facing, never stored, transmitted or compared. **Prose** — the only
rows in this file that ruling fits.

## D — array members (6 rows) — real

116/117/118 the singleton loop entries; 254/258 the publish maps; 262 the command
list. Each removal drops a registration.

## E — control flow (2 rows) — real

115 `ForeachEmptyIterable` (the singleton loop runs zero times) and 252
`IfNegated` (console-only publishing inverts).

## Tally

**56 of 62 rows are wiring with real runtime effect; 6 are prose.** The inverse
of what a mutator-family ruling would have produced.
