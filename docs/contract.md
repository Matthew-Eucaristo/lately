# JSON contract (schema_version 1)

`lately --json` prints one document. Within a schema version fields are only
added, never renamed or repurposed. Output is redacted unless `--no-redact`
is given (`"redacted": false` then).

```json
{
  "schema_version": 1,
  "tool": {"name": "lately", "version": "0.1.0"},
  "window": {"since": "2026-10-27T14:47:00Z", "until": "2026-10-27T15:02:00Z"},
  "tier": "user",
  "floor": "medium",
  "log_reaches_back": "2026-10-25T13:02:00Z",
  "counts": {"info": 0, "low": 0, "medium": 1, "high": 5, "critical": 0},
  "hidden": 2,
  "findings": [ … ],
  "limitations": ["The unified log reaches back to …", "…"],
  "notes": ["…"],
  "errors": {"log.tcc": "…"},
  "baseline": {"status": "loaded", "path": "~/Library/Application Support/lately/baseline.v1.json"},
  "redacted": true
}
```

- `counts` and `findings` cover rows at or above `floor` that are not hidden (Apple-signed below Medium, or marked known); `hidden` counts the rest. `--all` includes hidden rows.
- `baseline.status`: `fresh` (first run, nothing marked new), `loaded`, `damaged` (everything counts as first seen), `off` (`--no-baseline`).
- `errors` maps a source ID to why it failed; other sources still report.

A finding:

```json
{
  "id": "1b2c3d4e",
  "ts": "2026-10-27T14:49:07Z",
  "last": "2026-10-27T14:49:07Z",
  "count": 1,
  "level": "high",
  "category": "PERSIST",
  "rule": "persist.launch_agent",
  "mitre": ["T1543.001"],
  "title": "Launch agent added: com.foo.updater",
  "first_seen": true,
  "known": false,
  "approximate": false,
  "source": "persist",
  "subject": {"name": "com.foo.updater", "path": "/Library/Application Support/Foo/updater", "bundle_id": "com.foo.updater", "team_id": "ABCDE12345", "signer": "devid"},
  "fields": {"persist": "launch_agent", "change": "added", "plist": "/Library/LaunchAgents/com.foo.updater.plist"},
  "card": {"what": ["…"], "who": ["…"], "why": ["…"], "matters": ["…"], "do": ["…"], "raw": ["…"], "source": ["…"]}
}
```

- `level`: `info`, `low`, `medium`, `high`, `critical`.
- `category`: RESTART, CRASH, MALWARE, PERSIST, PERMIT, GATEKEEP, LAUNCH, EXEC, ACCOUNT, LOG, INSTALL, POWER, OTHER.
- `rule` IDs are listed by `lately rules`; an event no rule knows is `unclassified` (Low), never dropped.
- `signer`: `apple`, `devid`, `adhoc`, `unsigned`, or absent when not checked.
- `count` > 1 means a burst grouped into one row (same rule and subject within ten minutes, or the rule's burst window).
- `fields` are source-specific and may grow.

## `lately why-restart --json`

```json
{
  "schema_version": 1,
  "level": "medium",
  "verdict": {"kind": "stall", "title": "Hung shutdown", "explanation": "…", "inferred": true,
              "checks": [{"found": true, "name": "wtmp", "text": "…", "note": "not a clean restart"}], "notes": ["…"]},
  "evidence": {"boot": "…", "previous_boot": "…", "apple_silicon": true, "wtmp_readable": true,
               "shutdown_record": null, "breadcrumb_readable": true, "dumppanic_found_none": true,
               "watchdog_reset": true, "stall_reports": ["shutdown_stall_….shutdownStall"], "…": "…"}
}
```

`verdict.kind` is exactly one of `clean`, `update`, `panic`, `stall`, `unknown`.

## `lately net --json`

`{"schema_version": 1, "connections": [{"command", "pid", "proto", "name", "state"}], "traffic": [{"process", "pid", "bytes_in", "bytes_out"}], "limitation": "…"}`

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Nothing at or above the floor |
| 1 | Medium or High rows |
| 2 | At least one Critical row |
| 3 | The requested tier needs privileges (`capture` without root or Full Disk Access) |
| 4 | Usage error, unsupported platform, or every source failed |

`why-restart` uses 0 for a clean or update restart and 1 for the others.
