// Command fixtures captures redacted test fixtures from this Mac for the
// parser tests in internal/darwin/testdata.
//
//	go run ./tools/fixtures            read-only: sample recent history
//	go run ./tools/fixtures -trigger   first cause test events (see below)
//
// -trigger opens and quits TextEdit, crashes a throwaway shell with SIGSEGV,
// and writes then removes a LaunchAgent plist that is never loaded
// (~/Library/LaunchAgents/dev.lately.fixture.plist). It changes nothing
// else. Permission prompts, Gatekeeper overrides, panics and restarts cannot
// be scripted; trigger them by hand before a read-only run if you need them.
//
// Every string goes through lately's redactor, and fixtures keep only the
// fields the parsers read. Review the diff before committing anyway.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/Matthew-Eucaristo/lately/internal/darwin"
	"github.com/Matthew-Eucaristo/lately/internal/redact"
)

var red *redact.Redactor

func main() {
	trigger := flag.Bool("trigger", false, "cause test events first (opens TextEdit, crashes a shell, writes and removes an unloaded LaunchAgent)")
	last := flag.String("last", "1d", "how much log history to sample")
	out := flag.String("out", "internal/darwin/testdata", "output folder")
	flag.Parse()
	ctx := context.Background()
	home, _ := os.UserHomeDir()
	red = redact.New(darwin.Identity(ctx, home))
	if *trigger {
		triggerEvents(home)
	}
	must(os.MkdirAll(filepath.Join(*out, "reports"), 0o755))
	for _, l := range darwin.Lenses() {
		logLens(*out, l, *last)
	}
	reports(*out, home)
	cmdText(*out, "pmset.txt", pmsetExcerpt())
	cmdText(*out, "last_reboot.txt", run("/usr/bin/last", "reboot"))
	cmdText(*out, "last_shutdown.txt", run("/usr/bin/last", "shutdown"))
	cmdText(*out, "systemextensionsctl.txt", run("/usr/bin/systemextensionsctl", "list"))
	cmdText(*out, "codesign_apple.txt", runAll("/usr/bin/codesign", "-dv", "--verbose=2", "/bin/ls"))
	installHistory(*out)
	fmt.Println("done: review", *out, "before committing")
}

func triggerEvents(home string) {
	fmt.Println("triggering: TextEdit launch, shell crash, LaunchAgent write/remove")
	_ = exec.Command("/usr/bin/open", "-g", "-a", "TextEdit").Run()
	time.Sleep(3 * time.Second)
	_ = exec.Command("/usr/bin/osascript", "-e", `tell application "TextEdit" to quit`).Run()
	_ = exec.Command("/bin/sh", "-c", "kill -SEGV $$").Run()
	agent := filepath.Join(home, "Library/LaunchAgents/dev.lately.fixture.plist")
	data, _ := plist.MarshalIndent(map[string]any{"Label": "dev.lately.fixture", "ProgramArguments": []string{"/usr/bin/true"}}, plist.XMLFormat, "\t")
	must(os.MkdirAll(filepath.Dir(agent), 0o755))
	must(os.WriteFile(agent, data, 0o644))
	time.Sleep(2 * time.Second)
	_ = os.Remove(agent)
	time.Sleep(5 * time.Second) // let crash reports and log entries land
}

// logLens keeps up to 3 records per message template.
func logLens(out string, l *darwin.LogSource, last string) {
	b := run(darwin.LogPath, "show", "--last", last, "--style", "ndjson", "--predicate", l.Lens.Predicate)
	perTemplate := map[string]int{}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var r darwin.Record
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Timestamp == "" {
			continue
		}
		if perTemplate[r.FormatString]++; perTemplate[r.FormatString] > 3 {
			continue
		}
		r.ProcessImagePath = red.String(r.ProcessImagePath)
		r.EventMessage = red.String(r.EventMessage)
		r.FormatString = red.String(r.FormatString)
		r.BootUUID = red.String(r.BootUUID)
		j, _ := json.Marshal(r)
		lines = append(lines, string(j))
		if len(lines) >= 60 {
			break
		}
	}
	lines = append(lines, `{"count":0,"finished":1}`)
	write(filepath.Join(out, "log_"+l.Lens.Name+".ndjson"), strings.Join(lines, "\n")+"\n")
}

// reports keeps one report per kind: the .ips header plus the body fields
// the parser reads, or a stub for text reports.
func reports(out, home string) {
	seen := map[string]bool{}
	for _, dir := range []string{filepath.Join(home, "Library/Logs/DiagnosticReports"), "/Library/Logs/DiagnosticReports"} {
		ents, _ := os.ReadDir(dir)
		sort.Slice(ents, func(i, j int) bool { return ents[i].Name() > ents[j].Name() })
		for _, ent := range ents {
			if ent.IsDir() {
				continue
			}
			path := filepath.Join(dir, ent.Name())
			e, ok := darwin.ReadReport(path, time.Now())
			k := e.Field("report_kind")
			if !ok || seen[k] {
				continue
			}
			seen[k] = true
			name := red.String(darwin.ReportName(ent.Name()))
			if filepath.Ext(ent.Name()) != ".ips" {
				write(filepath.Join(out, "reports", name), "(text report stub; lately reads only the file name)\n")
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			head, body, _ := bytes.Cut(data, []byte("\n"))
			var keep map[string]any
			_ = json.Unmarshal(body, &keep)
			slim := map[string]any{}
			for _, f := range []string{"procPath", "parentProc", "responsibleProc", "codeSigningTeamID", "exception", "termination"} {
				if v, ok := keep[f]; ok {
					slim[f] = v
				}
			}
			sb, _ := json.Marshal(slim)
			write(filepath.Join(out, "reports", name), red.String(string(head))+"\n"+red.String(string(sb))+"\n")
		}
	}
}

func pmsetExcerpt() []byte {
	var keep []string
	sc := bufio.NewScanner(bytes.NewReader(run("/usr/bin/pmset", "-g", "log")))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if strings.Contains(l, " Assertions ") && !strings.Contains(l, "Summary-") {
			continue
		}
		keep = append(keep, l)
	}
	if len(keep) > 300 {
		keep = keep[len(keep)-300:]
	}
	return []byte(strings.Join(keep, "\n") + "\n")
}

func installHistory(out string) {
	f, err := os.Open("/Library/Receipts/InstallHistory.plist")
	if err != nil {
		return
	}
	defer f.Close()
	var entries []map[string]any
	if plist.NewDecoder(f).Decode(&entries) != nil {
		return
	}
	if len(entries) > 6 {
		entries = entries[len(entries)-6:]
	}
	data, _ := plist.MarshalIndent(entries, plist.XMLFormat, "\t")
	write(filepath.Join(out, "InstallHistory.plist"), red.String(string(data)))
}

func cmdText(out, name string, b []byte) { write(filepath.Join(out, name), red.String(string(b))) }

func run(name string, args ...string) []byte {
	b, _ := exec.Command(name, args...).Output()
	return b
}

func runAll(name string, args ...string) []byte {
	b, _ := exec.Command(name, args...).CombinedOutput()
	return b
}

var (
	offsetStamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)? ?[+-]\d{4}`)
	fileStamp   = regexp.MustCompile(`\d{4}-\d{2}-\d{2}-\d{6}`)
	lastStamp   = regexp.MustCompile(`\w{3} \w{3} [ \d]\d \d{2}:\d{2}(:\d{2})?( \w+)?( \d{4})?`)
	localDates  = regexp.MustCompile(`(?m)^.*(creat=|Signed Time=).*\n`)
)

// write hides the local time zone: every timestamp becomes true UTC (not
// a relabelled local clock, which would still give the offset away), file
// name stamps are converted the same way, and lines with locale-formatted
// dates are dropped.
func write(path, s string) {
	s = localDates.ReplaceAllString(s, "")
	s = offsetStamp.ReplaceAllStringFunc(s, func(m string) string {
		for _, layout := range []string{"2006-01-02 15:04:05.000000-0700", "2006-01-02 15:04:05.00 -0700", "2006-01-02 15:04:05 -0700"} {
			if t, err := time.Parse(layout, m); err == nil {
				return t.UTC().Format(layout)
			}
		}
		return m
	})
	s = fileStamp.ReplaceAllStringFunc(s, utcFileStamp)
	if strings.HasPrefix(filepath.Base(path), "last_") {
		s = lastStamp.ReplaceAllStringFunc(s, func(m string) string {
			now := time.Now()
			if t, err := time.ParseInLocation("Mon Jan _2 15:04 2006", m+" "+strconv.Itoa(now.Year()), time.Local); err == nil {
				return t.UTC().Format("Mon Jan _2 15:04")
			}
			return "Thu Jan  1 00:00:00 UTC 2026" // the "wtmp begins" line
		})
	}
	must(os.WriteFile(filepath.Join(filepath.Dir(path), utcFileStamp(filepath.Base(path))), []byte(s), 0o644))
}

func utcFileStamp(m string) string {
	return fileStamp.ReplaceAllStringFunc(m, func(st string) string {
		if t, err := time.ParseInLocation("2006-01-02-150405", st, time.Local); err == nil {
			return t.UTC().Format("2006-01-02-150405")
		}
		return st
	})
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixtures:", err)
		os.Exit(1)
	}
}
