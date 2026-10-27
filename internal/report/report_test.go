package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/redact"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
)

func sample() ([]*rules.Finding, Meta) {
	now := time.Date(2026, 10, 27, 15, 2, 0, 0, time.UTC)
	evs := []event.Event{
		{TS: now.Add(-13 * time.Minute), Kind: "persist", Source: "persist", Subject: event.Subject{Name: "com.foo.updater", Path: "/Users/alice/Library/Application Support/Foo/updater", Signer: event.SignerDevID, TeamID: "ABCDE12345"},
			Fields: map[string]string{"persist": "launch_agent", "change": "added", "program": "/Users/alice/Library/Application Support/Foo/updater", "plist": "/Users/alice/Library/LaunchAgents/com.foo.updater.plist", "label": "com.foo.updater"}},
		{TS: now.Add(-8 * time.Minute), Kind: "crash", Source: "reports", Subject: event.Subject{Name: "Safari", BundleID: "com.apple.Safari"}, Fields: map[string]string{"report_kind": "crash"}},
		{TS: now.Add(-5 * time.Minute), Kind: "launch", Source: "log.launch", Subject: event.Subject{BundleID: "com.apple.Notes"}, Fields: map[string]string{"identity": "app"}},
	}
	m := Meta{Version: "test", Since: now.Add(-15 * time.Minute), Until: now, Window: "15m", Tier: "user", Floor: event.Medium,
		Baseline: baseline.Disable(), AppleSilicon: true}
	return rules.Builtin().Process(evs, nil), m
}

func TestTextAndExit(t *testing.T) {
	fs, m := sample()
	var b bytes.Buffer
	Text(&b, fs, m, redact.New(redact.Identity{Home: "/Users/alice", User: "alice"}))
	out := b.String()
	for _, want := range []string{"▲ HIGH  PERSIST   Launch agent added: com.foo.updater", "● MED   CRASH     Safari crashed", "1 hidden", "sudo lately capture", "LuLu", "Apple silicon"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "alice") {
		t.Error("user name leaked")
	}
	if ExitCode(fs, m) != ExitWarning {
		t.Errorf("exit %d", ExitCode(fs, m))
	}
	m.Floor = event.Critical
	if ExitCode(fs, m) != ExitClean {
		t.Error("nothing at critical should exit 0")
	}
}

func TestJSONIsRedacted(t *testing.T) {
	fs, m := sample()
	var b bytes.Buffer
	if err := JSON(&b, fs, m, redact.New(redact.Identity{Home: "/Users/alice", User: "alice"})); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "alice") {
		t.Error("JSON leaked the user name")
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schema_version", "tool", "window", "findings", "limitations", "counts", "baseline", "hidden"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("JSON lacks %q", k)
		}
	}
	f := doc["findings"].([]any)[0].(map[string]any)
	card := f["card"].(map[string]any)
	for _, k := range []string{"what", "who", "why", "matters", "do", "raw", "source"} {
		if _, ok := card[k]; !ok {
			t.Errorf("card lacks %q", k)
		}
	}
}

func TestCardSections(t *testing.T) {
	fs, _ := sample()
	var labels []string
	for _, s := range Card(fs[len(fs)-1], nil) {
		labels = append(labels, s.Label)
	}
	if strings.Join(labels, " ") != "WHAT WHO WHY MATTERS DO RAW SOURCE" {
		t.Errorf("sections %v", labels)
	}
}

func TestAncestryMarksBrokenChains(t *testing.T) {
	tr := ancestry.New("capture")
	tr.Put(ancestry.Node{PID: 200, PPID: 100, Path: "/usr/bin/osascript"})
	tr.Put(ancestry.Node{PID: 300, PPID: 200, Path: "/bin/zsh", Args: "zsh -c true"})
	out := strings.Join(AncestryLines(tr, 300, nil), "\n")
	if !strings.Contains(out, "chain broken: parent pid 100") || !strings.Contains(out, "zsh (300)") {
		t.Errorf("ancestry:\n%s", out)
	}
	if !strings.Contains(strings.Join(AncestryLines(tr, 999, nil), " "), "not in the capture") {
		t.Error("unknown pid must say so")
	}
}

func TestAllKeepsTheFloor(t *testing.T) {
	fs, m := sample()
	m.All, m.Floor = true, event.High
	for _, f := range Visible(fs, m) {
		if f.Level < event.High {
			t.Errorf("--all showed %s below the floor", f.Level)
		}
	}
	m.Floor = event.Info
	if len(Visible(fs, m)) != len(fs) {
		t.Error("--all at info should show everything")
	}
}

func TestJSONTimesAreUTC(t *testing.T) {
	fs, m := sample()
	m.Since, m.Until = m.Since.In(time.FixedZone("X", 7*3600)), m.Until.In(time.FixedZone("X", 7*3600))
	var b bytes.Buffer
	if err := JSON(&b, fs, m, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "+07:00") {
		t.Error("JSON leaks the local time zone")
	}
}
