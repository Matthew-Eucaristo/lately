# Design notes

## Lens measurements (validation step)

Measured 2026-10-27 on an Apple M4, macOS 27.0.1, with `/usr/bin/log show --style ndjson --last W --predicate P`. Seconds per lens, all lenses running in parallel; records returned in brackets.

| Lens | 15 min | 1 hour | 1 day |
| --- | --- | --- | --- |
| launch (RunningBoard) | 1.7 | 1.8 | 38.2 |
| tcc | 1.5 | 0.8 | 6.3 (10,304 lines → user decisions only) |
| gatekeeper | 1.4 | 0.9 | 6.2 (3,730) |
| xprotect | 1.4 | 1.0 | 3.0 (50) |
| btm | 1.4 | 1.0 | 3.2 (20) |
| panic | 1.4 | 1.0 | 3.1 (22) |
| kernel | 1.4 | 0.8 | 5.8 (0) |
| logerase | 1.5 | 1.1 | 12.6 (3, all lately's own queries) |
| **all 8 in parallel** | **1.8** | **1.8** | **38.3** |
| one union predicate | 2.0 | 3.8 | 97.2 |

- Every `log show` call costs about 1.4 s even when it returns nothing; cost then grows with window length, mostly with how much the subsystem logs. RunningBoard is the long pole at a day.
- Parallel lenses beat one union predicate by 2–2.5× on longer windows, so lately runs one child process per lens and streams rows as each finishes.
- `pmset -g log` has no filter and takes about 4–5 s, so it is read only for windows of an hour or more (and by the restart verdict).
- End to end (`lately --list`): 15 min ≈ 2.4 s, 1 h ≈ 5–9 s, 24 h ≈ 55 s.

## What the macOS 27 formats turned out to be

These were checked against real records while building v1; the fixtures in `internal/darwin/testdata` hold redacted samples.

- GUI app launches are RunningBoard `Now tracking process: [app<application.BUNDLE.N.N(uid)>:pid]`. `Executing launch request` only covers XPC services and extensions.
- TCC: one decision is three lines sharing a `msgID` (`AUTHREQ_CTX` service, `AUTHREQ_ATTRIBUTION` client, `AUTHREQ_RESULT` value and reason). Reason 2 (answered a prompt) and 3 (set by the user) are kept; entitlement (11) and policy (5) checks are thousands a day and dropped.
- Gatekeeper `GK evaluateScanResult` lines are mostly anonymous; only those naming an id or bundle are kept. No line marks a user override, so `gatekeep.override` is elevated-only.
- XProtect Remediator logs one `XPEvent.structured` JSON per plugin run; `NoThreatDetected` and `Success` are dropped, anything else is shown.
- BTM logs `registerLaunchItem: found existing item: … name=, type=, disposition=, identifier=, url=` on every login for known items. The wording for a brand-new item has not been observed; any named registration that is not "found existing" is treated as added (approximate).
- DumpPanic runs after every boot and narrates. It says `No paniclog data found` (so "paniclog" alone is not evidence), writes the breadcrumb (`write { "<boot UUID>" = ""; }` when there was no panic), and reports PMU boot faults; `wdog` there means a watchdog reset.
- `codesign` now names platform binaries `Authority=macOS Software Signing`.
- `log` records its own invocations (`log run noninteractively, parent: PID (name), args: …`), which is how `log erase` is detected and how lately's own queries are excluded.
- `/private/var/db/diagnostics/Persist` is listable without root; its oldest file gives the real log reach (19 hours on the test Mac, against the 12 days `log stats` claims).
- `.ips` headers carry `is_simulated: 1` for ExcUserFault reports; those processes did not crash.

## Open questions

- The `.ips` `bug_type` table beyond 309 (crash) and 298 (jetsam) is not documented by Apple; unknown codes fall back to the file name.
- eslogger's JSON shape is not a stable API; the synthetic fixture follows `eslogger --format json` on macOS 13–15 and needs a real capture.
- The BTM "new item" message, TCC grants made in System Settings, and Gatekeeper overrides without root have not been sampled. The incident kit (`go run ./tools/fixtures -trigger` plus manual steps) is how to collect them.
- MITRE IDs follow ATT&CK v20 as given in the design research; `log.erase` uses T1685.006 from that matrix.
