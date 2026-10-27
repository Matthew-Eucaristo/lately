// Command lately answers "what just happened on my Mac, and what mattered"
// from evidence macOS already keeps: the unified log, crash reports, power
// and boot records, install receipts and persistence locations. No root,
// no daemon, no AI. Run `lately -h` for usage.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/collect"
	"github.com/Matthew-Eucaristo/lately/internal/darwin"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/redact"
	"github.com/Matthew-Eucaristo/lately/internal/replay"
	"github.com/Matthew-Eucaristo/lately/internal/report"
	"github.com/Matthew-Eucaristo/lately/internal/restart"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
	"github.com/Matthew-Eucaristo/lately/internal/source"
	"github.com/Matthew-Eucaristo/lately/internal/ui"
)

var version = "" // set by -ldflags at release time

const usage = `lately - what just happened on my Mac, and what mattered.

Usage:
  lately [flags]                     timeline of the last 15 minutes (TUI in a terminal)
  lately why-restart [--json]        one verdict: why did my Mac restart?
  sudo lately capture [--save FILE]  elevated: live process ancestry via eslogger, until you quit
  lately net [--json]                live connections and traffic (no history exists)
  lately rules                       list the rules, levels and MITRE IDs
  lately forget                      delete the baseline file
  lately version

Reads only what macOS already keeps; never installs anything, never runs
in the background, never changes the system. Exit codes: 0 nothing at or
above the floor, 1 warnings, 2 critical, 3 needs privileges, 4 error.

Flags:
`

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func main() {
	err := run(os.Args[1:])
	var ee *exitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		if ee.err != nil {
			fmt.Fprintln(os.Stderr, "lately:", ee.err)
		}
		os.Exit(ee.code)
	case errors.Is(err, flag.ErrHelp):
	default:
		fmt.Fprintln(os.Stderr, "lately:", err)
		os.Exit(report.ExitError)
	}
}

func run(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "why-restart":
			return runRestart(args[1:])
		case "capture":
			return runCapture(args[1:])
		case "net":
			return runNet(args[1:])
		case "rules":
			return runRules()
		case "forget":
			return runForget()
		case "version":
			fmt.Println("lately", buildVersion())
			return nil
		}
	}
	return runTimeline(args)
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	return fs
}

func parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return &exitError{report.ExitError, nil}
	}
	if fs.NArg() > 0 {
		return &exitError{report.ExitError, fmt.Errorf("unexpected argument %q", fs.Arg(0))}
	}
	return nil
}

// common holds the flags every timeline-style command shares.
type common struct {
	since      string
	minLevel   string
	jsonOut    bool
	mdOut      bool
	list       bool
	all        bool
	noBaseline bool
	noRedact   bool
	capture    string
	replay     string
}

func (c *common) register(fs *flag.FlagSet) {
	fs.StringVar(&c.since, "since", "15m", "window: 5m, 15m, 1h, 24h, boot, or any duration")
	fs.StringVar(&c.minLevel, "min-level", "medium", "lowest level shown: info, low, medium, high, critical")
	fs.BoolVar(&c.jsonOut, "json", false, "print JSON and exit (redacted)")
	fs.BoolVar(&c.mdOut, "md", false, "print Markdown for an issue or chat (redacted)")
	fs.BoolVar(&c.list, "list", false, "print the timeline as text and exit (default when not a terminal)")
	fs.BoolVar(&c.all, "all", false, "include Apple and acknowledged rows that are hidden by default")
	fs.BoolVar(&c.noBaseline, "no-baseline", false, "run ephemeral: read and write no baseline, mark nothing NEW")
	fs.BoolVar(&c.noRedact, "no-redact", false, "show real user, host and path names in output")
	fs.StringVar(&c.capture, "capture", "", "also read a `FILE` saved by sudo lately capture --save")
	fs.StringVar(&c.replay, "replay", "", "show the sample events in `DIR` instead of this Mac (used by the demo)")
}

// env is what one run needs.
type env struct {
	home    string
	red     *redact.Redactor
	base    *baseline.Baseline
	set     *rules.Set
	meta    report.Meta
	sources []source.Source
	replay  *replay.Data

	sourcesFor func(time.Duration) []source.Source
}

func setup(ctx context.Context, c common) (*env, error) {
	if c.replay != "" {
		return setupReplay(c)
	}
	if runtime.GOOS != "darwin" {
		return nil, &exitError{report.ExitError, errors.New("lately reads macOS evidence; Linux and Windows sources are not written yet")}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	if os.Geteuid() == 0 && os.Getenv("SUDO_USER") != "" {
		if h := sudoHome(); h != "" {
			home = h
		}
	}
	floor, err := event.ParseLevel(c.minLevel)
	if err != nil {
		return nil, &exitError{report.ExitError, err}
	}
	window, since, err := parseWindow(ctx, c.since)
	if err != nil {
		return nil, &exitError{report.ExitError, err}
	}
	e := &env{home: home, set: rules.Builtin()}
	if !c.noRedact {
		e.red = redact.New(darwin.Identity(ctx, home))
	}
	if c.noBaseline {
		e.base = baseline.Disable()
	} else {
		p, err := baseline.DefaultPath()
		if err != nil {
			return nil, err
		}
		if os.Geteuid() == 0 {
			e.base = baseline.Disable() // never write a root-owned file into the user's folder
		} else {
			e.base = baseline.Open(p)
		}
	}
	e.sourcesFor = func(window time.Duration) []source.Source {
		srcs := darwin.Sources(home, window)
		if c.capture != "" {
			srcs = append(srcs, &darwin.ESLogger{File: c.capture})
		}
		return srcs
	}
	e.sources = e.sourcesFor(time.Since(since))
	reach, _ := darwin.LogReach()
	e.meta = report.Meta{Version: buildVersion(), Since: since, Until: time.Now(), Window: window, Tier: "user",
		Floor: floor, All: c.all, LogReach: reach, Baseline: e.base, AppleSilicon: runtime.GOARCH == "arm64",
		SourcesTotal: len(e.sources)}
	return e, nil
}

// setupReplay serves a sample folder instead of the system. It reads
// nothing from this Mac and works on any OS.
func setupReplay(c common) (*env, error) {
	floor, err := event.ParseLevel(c.minLevel)
	if err != nil {
		return nil, &exitError{report.ExitError, err}
	}
	now := time.Now()
	window, since, err := parseWindow(context.Background(), c.since)
	if err != nil || window == "since boot" {
		return nil, &exitError{report.ExitError, fmt.Errorf("bad --since %q for a replay", c.since)}
	}
	data, err := replay.Load(c.replay, now)
	if err != nil {
		return nil, &exitError{report.ExitError, err}
	}
	e := &env{set: rules.Builtin(), replay: data}
	e.home, _ = os.UserHomeDir()
	if !c.noRedact {
		e.red = redact.New(redact.Identity{Home: e.home})
	}
	// Sample data never touches the real baseline. LATELY_BASELINE names a
	// separate file (the demo uses one in its temp folder).
	e.base = baseline.Disable()
	if p := os.Getenv("LATELY_BASELINE"); p != "" && !c.noBaseline {
		e.base = baseline.Open(p)
	}
	if len(data.Capture) > 0 {
		// Rows the live capture would produce: flashes and non-process events.
		tree := ancestry.New("replayed capture")
		_ = darwin.ParseES(bytes.NewReader(data.Capture), func(ev event.Event) {
			tree.Add(ev)
			switch ev.Kind {
			case event.KindExit:
				if fl, ok := collect.Flash(tree, ev); ok {
					fl.Source = "replay:eslogger"
					data.Events = append(data.Events, fl)
				}
			case event.KindExec:
			default:
				ev.Source = "replay:eslogger"
				data.Events = append(data.Events, ev)
			}
		})
	}
	src := &replay.Source{Data: data}
	e.sourcesFor = func(time.Duration) []source.Source { return []source.Source{src} }
	e.sources = e.sourcesFor(0)
	e.meta = report.Meta{Version: buildVersion(), Since: since, Until: now, Window: window, Tier: "replay",
		Floor: floor, All: c.all, Baseline: e.base, AppleSilicon: true, SourcesTotal: 1, Replay: true}
	return e, nil
}

// restartFunc gathers restart evidence from the system or the replay.
func (e *env) restartFunc() func(context.Context) (restart.Evidence, error) {
	if e.replay != nil {
		return func(context.Context) (restart.Evidence, error) {
			if e.replay.Restart == nil {
				return restart.Evidence{}, errors.New("this replay has no restart.json")
			}
			return *e.replay.Restart, nil
		}
	}
	b := &darwin.Boots{Home: e.home, Reports: darwin.NewReports(e.home), Install: darwin.NewInstalls(e.home)}
	return func(ctx context.Context) (restart.Evidence, error) {
		boots, err := darwin.BootTimes(ctx)
		if err != nil {
			return restart.Evidence{}, err
		}
		return b.Evidence(ctx, boots, 0, true), nil
	}
}

// uiConfig builds the TUI configuration, including a replayed capture.
func (e *env) uiConfig() ui.Config {
	cfg := ui.Config{Meta: e.meta, Rules: e.set, Baseline: e.base, Redactor: e.red, Sources: e.sources,
		SourcesFor: e.sourcesFor, Home: e.home, Restart: e.restartFunc()}
	if e.replay != nil {
		cfg.NoNet = "Live connections are not shown while replaying sample data."
		if len(e.replay.Capture) > 0 {
			cfg.Tree = ancestry.New("replayed capture")
			_ = darwin.ParseES(bytes.NewReader(e.replay.Capture), cfg.Tree.Add)
		}
		if len(e.replay.Live) > 0 {
			src := e.sources[0].(*replay.Source)
			cfg.Followers = func() []source.Follower { return []source.Follower{src} }
		} else {
			cfg.NoFollow = "this sample has no live.ndjson"
		}
		return cfg
	}
	cfg.Followers = func() []source.Follower { return darwin.Followers(e.sourcesFor(0)) }
	return cfg
}

func sudoHome() string {
	u := os.Getenv("SUDO_USER")
	if u == "" || strings.ContainsAny(u, "/.") {
		return ""
	}
	return "/Users/" + u
}

// parseWindow understands 5m, 1h, 24h, 1d and "boot".
func parseWindow(ctx context.Context, s string) (string, time.Time, error) {
	now := time.Now()
	if s == "boot" {
		boots, err := darwin.BootTimes(ctx)
		if err != nil || len(boots) == 0 {
			return "", now, errors.New("cannot read the boot time")
		}
		return "since boot", boots[0], nil
	}
	if strings.HasSuffix(s, "d") {
		var n int
		if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 {
			return s, now.Add(-time.Duration(n) * 24 * time.Hour), nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return "", now, fmt.Errorf("bad --since %q (want 5m, 15m, 1h, 24h, 2d or boot)", s)
	}
	return s, now.Add(-d), nil
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt)
}

func runTimeline(args []string) error {
	fs := newFlags("lately")
	var c common
	c.register(fs)
	showVer := fs.Bool("version", false, "print version")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *showVer {
		fmt.Println("lately", buildVersion())
		return nil
	}
	ctx, cancel := signalContext()
	defer cancel()
	e, err := setup(ctx, c)
	if err != nil {
		return err
	}
	opts := collect.Options{Since: e.meta.Since, Until: e.meta.Until, Sources: e.sources, Baseline: e.base}
	interactive := isTerminal(os.Stdout) && isTerminal(os.Stdin)
	if c.jsonOut || c.mdOut || c.list || !interactive {
		res := collect.Collect(ctx, opts)
		fs := e.finish(res)
		switch {
		case c.jsonOut:
			if err := report.JSON(os.Stdout, fs, e.meta, e.red); err != nil {
				return err
			}
		case c.mdOut:
			report.Markdown(os.Stdout, fs, e.meta, e.red)
		default:
			report.Text(os.Stdout, fs, e.meta, e.red)
		}
		return exitFor(report.ExitCode(fs, e.meta))
	}
	m := ui.New(e.uiConfig())
	defer m.Close() // waits for follow's log stream children
	if _, err := runProgram(m); err != nil {
		return err
	}
	if err := e.base.Save(); err != nil {
		fmt.Fprintln(os.Stderr, "lately: baseline not saved:", err)
	}
	return nil
}

// finish classifies a collection, saves the baseline and fills meta.
func (e *env) finish(res *collect.Result) []*rules.Finding {
	fs := e.set.Process(res.Events, e.base)
	e.meta.Redactions = res.Redactions()
	e.meta.Errors = res.Errors
	e.meta.Notes = append(e.meta.Notes, res.Notes...)
	e.meta.SourcesFailed = len(res.Errors)
	if os.Getenv("LATELY_DEBUG") != "" {
		for id, d := range res.Elapsed {
			fmt.Fprintf(os.Stderr, "lately: %-16s %6.2fs %v\n", id, d.Seconds(), res.Errors[id])
		}
	}
	if err := e.base.Save(); err != nil {
		e.meta.Notes = append(e.meta.Notes, "baseline not saved: "+err.Error())
	}
	return fs
}

func exitFor(code int) error {
	if code == 0 {
		return nil
	}
	return &exitError{code, nil}
}

func runRestart(args []string) error {
	fs := newFlags("lately why-restart")
	jsonOut := fs.Bool("json", false, "print JSON (redacted)")
	noRedact := fs.Bool("no-redact", false, "show real names")
	replayDir := fs.String("replay", "", "use the restart.json in `DIR` instead of this Mac")
	if err := parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	e, err := setup(ctx, common{since: "15m", minLevel: "info", noBaseline: true, noRedact: *noRedact, replay: *replayDir})
	if err != nil {
		return err
	}
	ev, err := e.restartFunc()(ctx)
	if err != nil {
		return err
	}
	v := restart.Decide(ev)
	if *jsonOut {
		shared := ev.Clean(e.red.String)
		sv := restart.Decide(shared) // checks rebuilt from the cleaned evidence
		if err := writeJSON(map[string]any{"schema_version": report.SchemaVersion, "verdict": sv, "level": sv.Level.String(), "evidence": shared}); err != nil {
			return err
		}
		return exitFor(levelExit(v.Level))
	}
	for _, l := range report.RestartLines(v, ev) {
		fmt.Println(e.red.String(l))
	}
	return exitFor(levelExit(v.Level))
}

func levelExit(l event.Level) int {
	switch {
	case l == event.Critical:
		return report.ExitCritical
	case l >= event.Medium:
		return report.ExitWarning
	}
	return report.ExitClean
}

func runCapture(args []string) error {
	fs := newFlags("lately capture")
	save := fs.String("save", "", "also write eslogger's raw JSON lines to FILE (contains command lines: keep it private)")
	var c common
	c.register(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	es := &darwin.ESLogger{}
	ctx, cancel := signalContext()
	defer cancel()
	if cp := es.Probe(ctx); !cp.Available {
		return &exitError{report.ExitPrivs, errors.New(cp.Note)}
	}
	if *save != "" {
		f, err := os.OpenFile(*save, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		es.Save = f
	}
	e, err := setup(ctx, c)
	if err != nil {
		return err
	}
	e.meta.Tier = "elevated"
	e.meta.CaptureSince = time.Now()
	if !isTerminal(os.Stdout) || c.list || c.jsonOut || c.mdOut {
		return captureText(ctx, es, e)
	}
	cfg := e.uiConfig()
	cfg.Capture = es
	m := ui.New(cfg)
	_, err = runProgram(m)
	m.Close() // eslogger is gone before the --save file is closed
	return err
}

// captureText streams classified capture rows until interrupted.
func captureText(ctx context.Context, es *darwin.ESLogger, e *env) error {
	tree := ancestry.New("capture")
	fmt.Fprintln(os.Stderr, "lately: capturing with eslogger; press Ctrl-C to stop. Nothing before now is known.")
	note, err := es.Stream(ctx, func(ev event.Event) {
		tree.Add(ev)
		evs := []event.Event{ev}
		if ev.Kind == event.KindExit {
			if fl, ok := collect.Flash(tree, ev); ok {
				evs = []event.Event{fl}
			} else {
				return
			}
		}
		for _, f := range e.set.Process(evs, e.base) {
			if report.Shown(f, e.meta) {
				fmt.Println(report.RowText(f, e.red))
			}
		}
	})
	if note != "" {
		fmt.Fprintln(os.Stderr, "lately:", note)
	}
	if err != nil {
		return &exitError{report.ExitPrivs, err}
	}
	return nil
}

func runNet(args []string) error {
	fs := newFlags("lately net")
	jsonOut := fs.Bool("json", false, "print JSON (redacted)")
	noRedact := fs.Bool("no-redact", false, "show real addresses")
	if err := parse(fs, args); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	e, err := setup(ctx, common{since: "15m", minLevel: "info", noBaseline: true, noRedact: *noRedact})
	if err != nil {
		return err
	}
	conns, traffic, err := darwin.LiveNet(ctx)
	if err != nil {
		return err
	}
	for i := range conns {
		conns[i].Name = e.red.String(conns[i].Name)
	}
	if *jsonOut {
		return writeJSON(map[string]any{"schema_version": report.SchemaVersion, "connections": conns, "traffic": traffic, "limitation": darwin.NetLimit})
	}
	fmt.Println("Live connections (your processes only) · " + darwin.NetLimit)
	fmt.Println(strings.Repeat("─", 78))
	for _, c := range conns {
		if c.State == "" || c.State == "ESTABLISHED" {
			fmt.Printf("%-18s %6d  %-4s %s %s\n", c.Command, c.PID, c.Proto, c.Name, c.State)
		}
	}
	fmt.Println(strings.Repeat("─", 78))
	fmt.Println("Traffic since each process started (nettop), busiest first:")
	for i, t := range traffic {
		if i == 10 {
			break
		}
		fmt.Printf("%-28s %6d  in %10s  out %10s\n", t.Process, t.PID, human(t.BytesIn), human(t.BytesOut))
	}
	return nil
}

func human(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

func runRules() error {
	for _, r := range rules.Builtin().Rules {
		band := r.Level
		if r.Min != "" || r.Max != "" {
			band = fmt.Sprintf("%s (%s–%s)", r.Level, or(r.Min, r.Level), or(r.Max, r.Level))
		}
		fmt.Printf("%-24s %-9s %-26s %-8s %s\n", r.ID, r.Category, band, r.Tier, strings.Join(r.MITRE, ","))
	}
	return nil
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func runForget() error {
	p, err := baseline.DefaultPath()
	if err != nil {
		return err
	}
	removed, err := baseline.Forget(p)
	if err != nil {
		return err
	}
	if home, err := os.UserHomeDir(); err == nil {
		p = strings.Replace(p, home, "~", 1)
	}
	if removed {
		fmt.Println("Removed", p)
	} else {
		fmt.Println("No baseline at", p)
	}
	return nil
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return strings.TrimPrefix(bi.Main.Version, "v")
	}
	return "dev"
}

// runProgram runs the TUI and turns SIGTERM and SIGHUP into a normal quit,
// so Close still stops follow's log stream children and eslogger.
func runProgram(m tea.Model) (tea.Model, error) {
	// 20 frames a second is instant for keys; Bubble Tea's default of 60
	// wakes the renderer three times as often for nothing.
	p := tea.NewProgram(m, tea.WithFPS(20))
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sig)
	go func() {
		if _, ok := <-sig; ok {
			p.Quit()
		}
	}()
	return p.Run()
}
