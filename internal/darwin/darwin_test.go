package darwin

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/event"
)

func lensEvents(t *testing.T, lens, file string) []event.Event {
	t.Helper()
	src := LensByName(lens)
	if src == nil {
		t.Fatalf("no lens %q", lens)
	}
	f, err := os.Open(filepath.Join("testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []event.Event
	if err := src.Parse(f, func(e event.Event) { out = append(out, e) }); err != nil {
		t.Fatal(err)
	}
	for _, e := range out {
		if e.Source != "log."+lens || e.Field("predicate") == "" || e.TS.IsZero() {
			t.Errorf("event not stamped by its lens: %+v", e)
		}
	}
	return out
}

func TestCapturedFixturesParse(t *testing.T) {
	// Every captured lens fixture must parse without error, whatever it holds.
	for _, l := range Lenses() {
		lensEvents(t, l.Lens.Name, "log_"+l.Lens.Name+".ndjson")
	}
}

func TestBadRecordIsAnError(t *testing.T) {
	err := LensByName("launch").Parse(strings.NewReader("not json\n"), func(event.Event) {})
	if err == nil {
		t.Fatal("a changed log format must fail loudly")
	}
}

func TestLaunchLens(t *testing.T) {
	evs := lensEvents(t, "launch", "synthetic_launch.ndjson")
	if len(evs) != 3 {
		t.Fatalf("got %d events", len(evs))
	}
	if evs[0].Subject.BundleID != "com.apple.Terminal" || evs[0].Subject.PID != 70110 || evs[0].Field("identity") != "app" {
		t.Errorf("app launch: %+v", evs[0])
	}
	if evs[1].Subject.Name != "Google Chrome Helper (Aperitif)" || evs[1].Field("identity") != "anon" {
		t.Errorf("anon launch: %+v", evs[1])
	}
	if evs[2].Subject.BundleID != "com.apple.WebKit.GPU" || evs[2].Subject.Responsible != "com.apple.Safari" {
		t.Errorf("xpc launch should name its app: %+v", evs[2].Subject)
	}
	captured := lensEvents(t, "launch", "log_launch.ndjson")
	if len(captured) == 0 {
		t.Error("captured launch fixture yielded nothing")
	}
}

func TestTCCLensKeepsOnlyPeopleDecisions(t *testing.T) {
	evs := lensEvents(t, "tcc", "synthetic_tcc.ndjson")
	if len(evs) != 1 {
		t.Fatalf("want only the answered prompt, got %d", len(evs))
	}
	e := evs[0]
	if e.Subject.BundleID != "com.example.foo" || e.Field("service_name") != "Screen Recording" ||
		e.Field("decision") != "allowed" || e.Field("powerful") != "yes" || !e.Approx {
		t.Errorf("tcc decision: %+v", e)
	}
	if got := lensEvents(t, "tcc", "log_tcc.ndjson"); len(got) != 0 {
		t.Errorf("policy-only checks must not become events, got %d", len(got))
	}
}

func TestPanicLens(t *testing.T) {
	evs := lensEvents(t, "panic", "synthetic_panic.ndjson")
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Field("evidence"))
	}
	if strings.Join(kinds, ",") != "watchdog,no_panic,panic,no_panic" {
		t.Errorf("evidence = %v", kinds)
	}
	// The real capture of a hung shutdown must not read as a panic.
	for _, e := range lensEvents(t, "panic", "log_panic.ndjson") {
		if e.Field("evidence") == "panic" {
			t.Errorf("false panic from %q", e.Raw)
		}
	}
}

func TestXProtectLens(t *testing.T) {
	evs := lensEvents(t, "xprotect", "synthetic_xprotect.ndjson")
	if len(evs) != 2 {
		t.Fatalf("NoThreatDetected must be dropped; got %d events", len(evs))
	}
	if evs[0].Field("threat") != "yes" || evs[1].Field("threat") != "" || evs[1].Field("status") != "PluginTimedOut" {
		t.Errorf("xprotect: %+v / %+v", evs[0].Fields, evs[1].Fields)
	}
}

func TestBadTimestampIsAnError(t *testing.T) {
	in := `{"timestamp":"yesterday","eventMessage":"Now tracking process: [anon<x>(501):1]"}` + "\n"
	if err := LensByName("launch").Parse(strings.NewReader(in), func(event.Event) {}); err == nil {
		t.Fatal("an unreadable timestamp must not be dropped silently")
	}
}

func TestLogEraseAnyArgv0(t *testing.T) {
	for _, args := range []string{"'x' 'erase' '--all'", "'./log' 'erase'"} {
		r := Record{Timestamp: "2026-10-27 13:20:00.000000+0000", EventMessage: "log run noninteractively, parent: 9 (sh), args: " + args}
		var got []event.Event
		parseLogErase(r, func(e event.Event) { got = append(got, e) })
		if len(got) != 1 {
			t.Errorf("%s: not detected", args)
		}
	}
}

func TestLogEraseIgnoresQueries(t *testing.T) {
	evs := lensEvents(t, "logerase", "synthetic_logerase.ndjson")
	if len(evs) != 1 || evs[0].Subject.Name != "zsh" {
		t.Fatalf("want only the real erase, got %+v", evs)
	}
	if got := lensEvents(t, "logerase", "log_logerase.ndjson"); len(got) != 0 {
		t.Errorf("lately's own queries counted as erase: %d", len(got))
	}
}

func TestBTMLens(t *testing.T) {
	for _, e := range lensEvents(t, "btm", "log_btm.ndjson") {
		if e.Field("change") != "existing" {
			t.Errorf("captured BTM lines are re-registrations, got %q", e.Field("change"))
		}
	}
	evs := lensEvents(t, "btm", "synthetic_btm_added.ndjson")
	if len(evs) != 1 || evs[0].Field("change") != "added" || evs[0].Subject.BundleID != "com.example.foo.updater" ||
		evs[0].Subject.Path != "/Library/LaunchAgents/com.example.foo.updater.plist" {
		t.Fatalf("btm add: %+v", evs)
	}
}

func TestGatekeeperLensSkipsAnonymousScans(t *testing.T) {
	if got := lensEvents(t, "gatekeeper", "log_gatekeeper.ndjson"); len(got) != 0 {
		t.Errorf("anonymous scans should be dropped, got %d", len(got))
	}
	r := Record{Timestamp: "2026-10-27 12:06:34.000000+0000",
		EventMessage: "GK evaluateScanResult: 2, PST: (path: ab12), (team: EQHXZ8M8AV), (id: com.google.GoogleUpdater), (bundle_id: NOT_A_BUNDLE), 0, 0, 1, 0, 0, 0, 0"}
	var got []event.Event
	parseGatekeeper(r, func(e event.Event) { got = append(got, e) })
	if len(got) != 1 || got[0].Subject.TeamID != "EQHXZ8M8AV" || got[0].Subject.BundleID != "" {
		t.Errorf("gatekeeper: %+v", got)
	}
}

// report finds a captured report fixture by its name prefix (names carry
// the capture's UTC time).
func report(t *testing.T, prefix string) string {
	t.Helper()
	m, _ := filepath.Glob(filepath.Join("testdata/reports", prefix+"*"))
	if len(m) != 1 {
		t.Fatalf("fixture %s*: %v", prefix, m)
	}
	return m[0]
}

func TestReports(t *testing.T) {
	want := map[string]string{
		"ExcUserFault_textunderstandingd-": "fault",
		"JetsamEvent-":                     "jetsam",
		"pnpm-":                            "crash",
		"shutdown_stall_":                  "stall",
		"spotlightknowledged_":             "resource",
		"Safari_":                          "hang",
	}
	for prefix, kind := range want {
		e, ok := ReadReport(report(t, prefix), time.Time{})
		if !ok || e.Field("report_kind") != kind {
			t.Errorf("%s: kind %q, want %q", prefix, e.Field("report_kind"), kind)
		}
		if e.TS.IsZero() {
			t.Errorf("%s: no time", prefix)
		}
	}
	e, _ := ReadReport(report(t, "pnpm-"), time.Time{})
	if e.Subject.Name != "pnpm" || e.Field("exception") == "" {
		t.Errorf("crash body not read: %+v", e)
	}
	if got := ReportName("Google Chrome_2026-10-26-213201_Some-Host.diag"); got != "Google Chrome_2026-10-26-213201.diag" {
		t.Errorf("host name not dropped: %q", got)
	}
	e, _ = ReadReport(report(t, "JetsamEvent-"), time.Time{})
	if e.Subject.Name != "processes" {
		t.Errorf("jetsam subject: %q", e.Subject.Name)
	}
}

func TestPowerLog(t *testing.T) {
	f, err := os.Open("testdata/pmset.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d, err := ParsePowerLog(f)
	if err != nil || len(d.Lines) == 0 {
		t.Fatalf("pmset: %v, %d lines", err, len(d.Lines))
	}
	for i := 1; i < len(d.Lines); i++ {
		if d.Lines[i].TS.Before(d.Lines[i-1].TS) {
			t.Fatal("lines not sorted")
		}
	}
	last := d.Lines[len(d.Lines)-1].TS
	if _, ok := d.Before(last.Add(time.Second)); !ok {
		t.Error("Before found nothing")
	}
	if src, _ := d.SourceBefore(last.Add(time.Second)); src == "" {
		t.Error("power source not found in summaries")
	}
	l := PowerLine{TS: last, Type: "Wake", Details: "DarkWake to FullWake from Deep Idle [CDNVA] : due to UserActivity Assertion Using AC (Charge:80%)"}
	if e := l.event(); e.Field("reason") != "UserActivity Assertion" {
		t.Errorf("reason = %q", e.Field("reason"))
	}
}

func TestParseLastInfersYears(t *testing.T) {
	now := time.Date(2026, 1, 3, 12, 0, 0, 0, time.Local)
	in := "reboot time                                Fri Jan  2 09:00\nreboot time                                Wed Dec 31 22:41\n\nwtmp begins Thu Jul 30 04:03:04 UTC 2025\n"
	got := ParseLast(strings.NewReader(in), "reboot", now)
	if len(got) != 2 || got[0].Year() != 2026 || got[1].Year() != 2025 || got[1].Month() != time.December {
		t.Fatalf("got %v", got)
	}
	leap := ParseLast(strings.NewReader("reboot time                                Thu Feb 29 10:00\n"), "reboot", time.Date(2026, 3, 5, 0, 0, 0, 0, time.Local))
	if len(leap) != 1 || leap[0].Year() != 2024 {
		t.Errorf("Feb 29 should fall back to the last leap year: %v", leap)
	}
	f, _ := os.ReadFile("testdata/last_reboot.txt")
	if len(ParseLast(bytes.NewReader(f), "reboot", time.Now())) == 0 {
		t.Error("captured last output yielded nothing")
	}
}

func TestBreadcrumb(t *testing.T) {
	in := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>UUID-1</key><string></string><key>UUID-2</key><string>/Library/Logs/DiagnosticReports/x.panic</string></dict></plist>`
	m, err := ReadBreadcrumb(strings.NewReader(in))
	if err != nil || m["UUID-1"] != "" || m["UUID-2"] == "" {
		t.Fatalf("breadcrumb: %v %v", m, err)
	}
}

func TestInstalls(t *testing.T) {
	f, err := os.Open("testdata/InstallHistory.plist")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var got []event.Event
	if err := ParseInstallHistory(f, func(e event.Event) { got = append(got, e) }); err != nil || len(got) == 0 {
		t.Fatalf("install history: %v (%d)", err, len(got))
	}
	if got[0].TS.IsZero() || got[0].Subject.Name == "" {
		t.Errorf("entry: %+v", got[0])
	}
	log := "2026-10-25 18:52:40+00 host installd[1123]: PackageKit: request=PKInstallRequest <1 packages, destination=/>\n" +
		"2026-10-25 18:52:40+00 host installd[1123]: PackageKit: packages=(\n" +
		"\t    \"PKLeopardPackage <id=com.example.pkg, version=3.2, url=file:///tmp/x.pkg>\"\n\t)\n" +
		"2026-10-25 18:52:41+00 host installd[1123]: something else\n" +
		"\t    \"PKLeopardPackage <id=com.example.ignored, version=1, url=file:///tmp/y.pkg>\"\n"
	got = nil
	if err := ParseInstallLog(strings.NewReader(log), func(e event.Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Subject.BundleID != "com.example.pkg" || got[0].Field("version") != "3.2" || got[0].Field("by") != "installd" {
		t.Fatalf("install.log: %+v", got)
	}
}

func TestCodesign(t *testing.T) {
	b, _ := os.ReadFile("testdata/codesign_apple.txt")
	if s := ParseCodesign(string(b)); s.Signer != event.SignerApple {
		t.Errorf("/bin/ls signer = %q", s.Signer)
	}
	cases := map[string]string{
		"Authority=Developer ID Application: Foo Inc (ABCDE12345)\nTeamIdentifier=ABCDE12345\n": event.SignerDevID,
		"Signature=adhoc\nTeamIdentifier=not set\n":                                             event.SignerAdhoc,
		"/tmp/x: code object is not signed at all\n":                                            event.SignerUnsigned,
		"/tmp/x: No such file or directory\n":                                                   event.SignerUnknown,
	}
	for in, want := range cases {
		if got := ParseCodesign(in).Signer; got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestSnapshotsParse(t *testing.T) {
	b, _ := os.ReadFile("testdata/systemextensionsctl.txt")
	if items := SysextItems(b); len(items) != 0 {
		t.Errorf("no extensions expected, got %+v", items)
	}
	row := "--- com.apple.system_extension.network_extension\nenabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n*\t*\tABCDE12345\tcom.example.filter (1.0/1)\tFoo Filter\t[activated enabled]\n0 extension(s)\nweird new line\n"
	items := SysextItems([]byte(row))
	if len(items) != 2 || items[0].Subject.BundleID != "com.example.filter" || items[0].Subject.TeamID != "ABCDE12345" ||
		items[0].Fields["state"] != "activated enabled" {
		t.Fatalf("sysext: %+v", items)
	}
	if items[1].Key != "sysext:weird new line" {
		t.Errorf("unknown lines must still be tracked: %+v", items[1])
	}
	cron := CrontabItems([]byte("# comment\nMAILTO=\"\"\n*/5 * * * * /usr/local/bin/foo\n"))
	if len(cron) != 1 || cron[0].Fields["entry"] != "*/5 * * * * /usr/local/bin/foo" {
		t.Errorf("cron: %+v", cron)
	}
}

func TestPersistenceHistory(t *testing.T) {
	home := t.TempDir()
	agents := filepath.Join(home, "Library/LaunchAgents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	pl := `<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>Label</key><string>com.example.agent</string><key>ProgramArguments</key><array><string>/nonexistent/agent</string><string>--quiet</string></array><key>RunAtLoad</key><true/></dict></plist>`
	if err := os.WriteFile(filepath.Join(agents, "com.example.agent.plist"), []byte(pl), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agents, "broken.plist"), []byte("not a plist"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".zshrc"), []byte("export X=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p := &Persistence{Home: home}
	var got []event.Event
	now := time.Now()
	if err := p.History(t.Context(), now.Add(-time.Minute), now.Add(time.Minute), func(e event.Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	byPersist := map[string]event.Event{}
	for _, e := range got {
		byPersist[e.Field("persist")+":"+e.Subject.Name] = e
	}
	a, ok := byPersist["launch_agent:com.example.agent"]
	if !ok || a.Field("program") != "/nonexistent/agent" || a.Field("run_at_load") != "yes" || a.Field("args") != "--quiet" {
		t.Fatalf("agent: %+v (all: %v)", a, byPersist)
	}
	if _, ok := byPersist["launch_agent:broken.plist"]; !ok {
		t.Error("an unparseable plist must still be reported")
	}
	if _, ok := byPersist["shell_rc:.zshrc"]; !ok {
		t.Error("new .zshrc not reported")
	}
	items, _ := p.Snapshot(t.Context())
	for _, it := range items {
		if it.Group == "" {
			t.Errorf("item without a group: %+v", it)
		}
	}
	if len(items) < 3 {
		t.Errorf("snapshot: %d items", len(items))
	}
}

func TestESLogger(t *testing.T) {
	f, err := os.Open("testdata/synthetic_eslogger.ndjson")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tree := ancestry.New("capture")
	kinds := map[string]int{}
	var all []event.Event
	if err := ParseES(f, func(e event.Event) {
		tree.Add(e)
		kinds[e.Kind]++
		all = append(all, e)
	}); err != nil {
		t.Fatal(err)
	}
	if kinds[event.KindExec] != 4 || kinds[event.KindExit] != 1 || kinds[event.KindPersist] != 1 ||
		kinds[event.KindAuth] != 1 || kinds[event.KindPermit] != 1 || kinds["unclassified"] != 1 {
		t.Errorf("kinds = %v", kinds)
	}
	zsh, ok := tree.Get(71203)
	if !ok || zsh.Path != "/bin/zsh" || zsh.PPID != 70100 || !strings.Contains(zsh.Args, "curl") {
		t.Fatalf("zsh node: %+v", zsh)
	}
	if l, ok := zsh.Lived(); !ok || l > time.Second {
		t.Errorf("lifetime %v", l)
	}
	c := tree.Chain(71203)
	if c.Broken || len(c.Nodes) != 4 || c.Nodes[0].PID != 1 || c.Nodes[1].TeamID != "ABCDE12345" {
		t.Errorf("chain should run launchd → helper → osascript → zsh: %+v", c)
	}
	for _, e := range all {
		if e.Kind == event.KindPermit && (e.Field("service_name") != "Accessibility" || e.Field("decision") != "allowed") {
			t.Errorf("tcc_modify: %+v", e.Fields)
		}
		if e.Kind == event.KindPersist && e.Subject.Path != "/Library/Application Support/Foo/updater" {
			t.Errorf("btm add path: %+v", e.Subject)
		}
	}
	if _, err := ParseESLine([]byte("{broken")); err == nil {
		t.Error("unreadable eslogger line must be an error")
	}
}

func TestLiveSnapshotsParse(t *testing.T) {
	lsof := "COMMAND     PID USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME\nfoo   650 USER    9u  IPv4 0xc0      0t0  TCP 10.0.0.2:5000->1.2.3.4:443 (ESTABLISHED)\n"
	if cs := ParseLsof([]byte(lsof)); len(cs) != 1 || cs[0].State != "ESTABLISHED" || cs[0].PID != 650 {
		t.Errorf("lsof: %+v", cs)
	}
	nt := "time,,interface,state,bytes_in,bytes_out,\n12:02:44.4,launchd.1,,,0,0,\n12:02:44.4,apsd.386,,,159469,19345,\n"
	if ts := ParseNettop([]byte(nt)); len(ts) != 2 || ts[0].Process != "apsd" || ts[0].BytesIn != 159469 {
		t.Errorf("nettop: %+v", ts)
	}
	tr := ParsePS([]byte("    1     0 /sbin/launchd\n  500     1 /Applications/Foo.app/Contents/MacOS/Foo Helper\n"))
	if n, ok := tr.Get(500); !ok || n.PPID != 1 || n.Name() != "Foo Helper" {
		t.Errorf("ps: %+v", n)
	}
}
