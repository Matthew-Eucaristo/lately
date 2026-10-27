# Test fixtures

`log_*.ndjson`, `pmset.txt`, `last_*.txt`, `systemextensionsctl.txt`,
`codesign_apple.txt`, `InstallHistory.plist` and `reports/` were captured on
macOS 27.0.1 (Apple silicon) with `go run ./tools/fixtures`, which keeps only
the fields lately parses, runs everything through lately's redactor and
rewrites time zones to UTC. Recapture after a macOS update and diff.

`synthetic_*` files are hand-written in the same record shapes for events
that cannot be produced on demand or did not occur in the capture window
(an app launch, a TCC prompt answered, a watchdog reset, an XProtect
detection, `log erase`, eslogger output). Their message text follows
records seen on macOS 27; the eslogger lines follow the JSON shape of
`eslogger --format json` and are unverified until someone captures real
ones with `sudo lately capture --save`.
