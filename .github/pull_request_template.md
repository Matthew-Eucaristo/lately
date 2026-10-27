**What and why**

**Checklist**
- [ ] `gofmt -l .` is empty, `go vet ./...`, `GOOS=linux go vet ./...` and `go test -race ./...` pass
- [ ] New rule: YAML entry with What / Matters / Do, level band, tier, MITRE ID if one applies, and a test case
- [ ] New lens: predicate on subsystem and message template, fixture, test, and 15m / 1h / 1d timings
- [ ] New blind spot named in `report.Limitations`
- [ ] Still read-only: nothing changes the system; no new file written outside the baseline
- [ ] No real paths, usernames, host names, project names or time zones in code, tests, fixtures or docs
