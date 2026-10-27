# lately

Terminal tool that answers "what just happened on my Mac, and what mattered" from evidence macOS already keeps, with no root, no daemon and no AI. Go + Bubble Tea v2 + Lip Gloss v2 (+ howett.net/plist, go.yaml.in/yaml/v3). macOS only for now; CI also tests on Linux. Family rules: `../AGENTS.md` (lately is a diagnostics tool, not a cleaner: it never removes or changes anything).

## Layout
- `internal/event` — `Event`, `Subject`, five `Level`s (Sigma names) and signer classes.
- `internal/source` — the cross-platform `Source` / `Snapshotter` / `Streamer` interfaces. A Linux or Windows port is a new package beside `internal/darwin`; rules and views stay.
- `internal/darwin` — macOS sources. Each shells out to an Apple tool or reads a user-readable file: 8 unified-log lenses (`lenses.go`, predicates in `logshow.go`), DiagnosticReports (`reports.go`), boots/wtmp/breadcrumb/restart evidence (`boot.go`), pmset (`power.go`), installs, persistence and snapshots, codesign, live net, ps, eslogger (elevated). Parsers take an `io.Reader`; fixtures in `testdata/` (README there explains captured vs synthetic).
- `internal/rules` — embedded `data/rules.yaml` + engine: first match wins, band-clamped adjustments (unsigned +1, first seen +1, Apple −1, known −1), burst grouping, install correlation. The last rule must match everything.
- `internal/baseline` — salted-hash first-seen/known/snapshot file. `internal/restart` — the single restart verdict. `internal/ancestry` — process trees. `internal/redact` — placeholders. `internal/collect` — parallel source runner, snapshot diff, flash detection. `internal/report` — rows, cards, JSON/Markdown, limitations, exit codes. `internal/ui` — TUI (fell's layout: brand + tier badge header, aligned columns, detail pane, one limitation line, key hints; blocking work only in commands). `internal/replay` — `--replay DIR` sample data (events, capture, restart evidence; times shifted to now). `tools/fixtures` — fixture capture. `demo/` — `demo.tape`, `setup.sh` (temp HOME, `LATELY_BASELINE`), `sample/` generic data, `demo.gif`.

## Invariants
- Read-only: lately never changes the system, never installs or schedules anything, never prompts for elevation. Cards print commands; they never run them. The only file it writes is the baseline (never as root) and exports/captures the user explicitly saves.
- Fail closed: an unparseable log line is an error, an unknown event shape is an "unclassified" Low row, a damaged baseline counts everything as first seen and is never overwritten. Nothing is silently dropped except documented noise (policy-only TCC checks, NoThreatDetected, anonymous Gatekeeper scans, DumpPanic narration).
- Panic evidence must be unambiguous (`panic(cpu`, a non-empty breadcrumb write); "paniclog" alone appears in "No paniclog data found".
- Every limitation is named in the UI (`report.Limitations`). New blind spots get a line there.
- No PII: output and exports are redacted by default; fixtures go through the redactor with time zones rewritten to UTC. Baseline stores hashes only.
- `--json` (`docs/contract.md`) only grows within a schema version; exit codes 0/1/2/3/4 are fixed.
- Snapshot groups that fail to read keep their previous baseline entries; a partial or cancelled snapshot is never saved (no false "added" next run). First-seen answers come from the baseline as loaded, so saving mid-run never changes them.
- Replays never read the system and never touch the real baseline (only `LATELY_BASELINE` if set).
- Always spell `/usr/bin/log` (`log` is a zsh builtin); the `logerase` lens ignores lately's own queries.

## Demo
`vhs demo/demo.tape` from the repo root records `demo/demo.gif` from `demo/sample` only (never the real Mac); `demo/sample/seen` primes a temp baseline so NEW shows. Check every frame for PII and keep the GIF under ~1 MB. Regenerate locally, never in CI.

## Verify
`gofmt -l .` (empty), `go vet ./...`, `GOOS=linux go vet ./...`, `go test -race ./...`. On a real Mac use read-only runs with `--no-baseline`: `lately --list --since 1h --no-baseline`, `lately why-restart`, `LATELY_DEBUG=1` prints per-source timings. Recapture fixtures with `go run ./tools/fixtures` (read-only) and review the diff for PII; `-trigger` causes test events and is for maintainers to run deliberately.
