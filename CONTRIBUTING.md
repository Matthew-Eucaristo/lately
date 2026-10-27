# Contributing

Thanks for helping. lately aims to stay small, read-only and easy to audit.

## Development

```sh
gofmt -l .
go vet ./...
GOOS=linux go vet ./...
go test -race ./...
go run . --list --since 1h --no-baseline
LATELY_DEBUG=1 go run . --list --no-baseline   # per-source timings
```

`go run . --replay demo/sample` shows the sample data without reading this Mac. Set `LATELY_BASELINE=/tmp/x.json` to give replays a throwaway baseline.

Tests run against fixtures in `internal/darwin/testdata`, so they pass on Linux CI without a Mac's log. Never test against a real Mac in a way that changes it: lately itself is read-only, and `--no-baseline` keeps it from writing even its own file.

## Ground rules

- **Read-only.** lately never changes the system, never installs, loads or schedules anything, and never prompts for elevation. Cards may print commands; they never run them.
- **Fail closed.** If a format cannot be read, say so (an error, or an `unclassified` row). Never guess and never silently drop an event.
- **Name the blind spot.** If a source cannot see something, add a line to `report.Limitations` instead of showing less.
- **A new rule** is a YAML entry in `internal/rules/data/rules.yaml` (title, level band, tier, MITRE ID if one applies, and What / Matters / Do text) plus a case in `rules_test.go`. Keep the levels honest: High means "look at even one".
- **A new log lens** is one `Lens` in `internal/darwin/logshow.go` with a predicate on subsystem *and* message template, a parser in `lenses.go`, a fixture and a test. Measure it over 15 minutes, 1 hour and 1 day and put the numbers in the PR.
- **Fixtures.** `go run ./tools/fixtures` captures redacted samples read-only. `-trigger` deliberately causes test events (opens TextEdit, crashes a throwaway shell, writes and removes an unloaded LaunchAgent); run it only on your own Mac. Hand-written fixtures are named `synthetic_*` and say so in `testdata/README.md`. Read every fixture diff for names, paths, hosts and time zones before committing.
- **Demo.** `vhs demo/demo.tape` re-records `demo/demo.gif` from `demo/sample`. Edit the sample data rather than recording a real Mac, check every frame for PII, and keep the GIF small.
- **A new platform** (Linux journald, Windows event log) implements `internal/source.Source` in its own package; rules and views should not change.
- **Licences.** Only MIT, BSD or Apache-2.0 code may be imported or copied. GPL, AGPL, EUPL and CC-NC projects (Objective-See, Hayabusa, Chainsaw, TrueTree, Velociraptor) are ideas only. Elastic's rules must not be bundled.
- The JSON contract (`docs/contract.md`) only grows within a schema version.
- Keep dependencies to Charm modules, `howett.net/plist` and `go.yaml.in/yaml/v3` unless there is a strong reason.
- No real paths, usernames, host names, project names or time zones in code, tests, docs or fixtures.
- Pull requests are squash-merged, so the PR title becomes the commit and the release-notes entry. Use a conventional prefix: `feat:`, `fix:`, `docs:`, `test:`, `ci:` or `chore:` (the last four are left out of release notes).

## Reporting security issues

See [SECURITY.md](SECURITY.md).
