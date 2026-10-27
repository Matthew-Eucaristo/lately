// Package ui is the interactive Bubble Tea front end: the timeline, event
// cards, the restart verdict, process ancestry, live connections and the
// redacted export preview.
package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/collect"
	"github.com/Matthew-Eucaristo/lately/internal/darwin"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/redact"
	"github.com/Matthew-Eucaristo/lately/internal/report"
	"github.com/Matthew-Eucaristo/lately/internal/restart"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Config is what main hands the UI.
type Config struct {
	Meta     report.Meta
	Rules    *rules.Set
	Baseline *baseline.Baseline
	Redactor *redact.Redactor
	Sources  []source.Source
	// SourcesFor rebuilds the sources when the window changes (pmset is
	// only read for longer windows). Optional.
	SourcesFor func(window time.Duration) []source.Source
	Home       string
	// Restart gathers the evidence for the restart view.
	Restart func(context.Context) (restart.Evidence, error)
	Capture *darwin.ESLogger // set only for `sudo lately capture`
	// Tree is a prebuilt process tree (a replayed capture). Optional.
	Tree *ancestry.Tree
	// NoNet, when set, says why live connections are not shown (replay).
	NoNet string
}

type view int

const (
	timelineView view = iota
	cardView
	restartView
	ancestryView
	netView
	exportView
	helpView
)

type groupBy int

const (
	byTime groupBy = iota
	byCategory
	bySubject
)

func (g groupBy) String() string { return [...]string{"time", "category", "app"}[g] }

var windows = []string{"5m", "15m", "1h", "24h", "boot"}

type (
	updateMsg struct {
		u   collect.Update
		gen int
	}
	closedMsg struct{ gen int }
	linesMsg  struct {
		v     view
		lines []string
	}
	statusMsg struct {
		text       string
		reclassify bool
	}
	windowMsg struct {
		label string
		since time.Time
	}
	capEventMsg event.Event
	capDoneMsg  struct {
		note string
		err  error
	}
)

// row is a group header (f == nil) or a finding.
type row struct {
	header string
	f      *rules.Finding
}

// Model is the TUI state. All mutation happens in Update.
type Model struct {
	cfg  Config
	meta report.Meta

	ctx     context.Context
	cancel  context.CancelFunc
	updates <-chan collect.Update
	gen     int // collection generation; stale updates are ignored
	pending map[string]bool
	loading bool
	sinceUI int // events since the last reclassify

	events   []event.Event
	findings []*rules.Finding

	view      view
	group     groupBy
	windowIdx int
	filter    string
	filtering bool
	cursor    int
	offset    int
	width     int
	height    int
	showRaw   bool
	status    string

	lines      []string // content of restart, ancestry, net and export views
	exportText string

	tree      *ancestry.Tree
	capChan   chan tea.Msg
	capNote   string
	capCancel context.CancelFunc
	capDone   chan struct{}
}

// New builds the model.
func New(cfg Config) *Model {
	m := &Model{cfg: cfg, meta: cfg.Meta, width: 100, height: 30, pending: map[string]bool{}}
	m.windowIdx = 1
	for i, w := range windows {
		if w == cfg.Meta.Window || cfg.Meta.Window == "since boot" && w == "boot" {
			m.windowIdx = i
		}
	}
	switch {
	case cfg.Capture != nil:
		m.tree = ancestry.New("capture")
		m.tree.Since = cfg.Meta.CaptureSince
	case cfg.Tree != nil:
		m.tree = cfg.Tree
	}
	return m
}

func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.startCollect()}
	if m.cfg.Capture != nil {
		cmds = append(cmds, m.startCapture())
	}
	return tea.Batch(cmds...)
}

func (m *Model) startCollect() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.events, m.findings, m.cursor, m.offset = nil, nil, 0, 0
	m.meta.Until = time.Now()
	if m.cfg.SourcesFor != nil {
		m.cfg.Sources = m.cfg.SourcesFor(m.meta.Until.Sub(m.meta.Since))
	}
	m.meta.Errors = map[string]error{}
	m.meta.Redactions = 0
	m.pending = map[string]bool{}
	for _, s := range m.cfg.Sources {
		m.pending[s.ID()] = true
	}
	m.loading = true
	m.gen++
	m.updates = collect.Stream(m.ctx, collect.Options{Since: m.meta.Since, Until: m.meta.Until,
		Sources: m.cfg.Sources, Baseline: m.cfg.Baseline})
	return waitUpdate(m.updates, m.gen)
}

func waitUpdate(ch <-chan collect.Update, gen int) tea.Cmd {
	return func() tea.Msg {
		u, ok := <-ch
		if !ok {
			return closedMsg{gen}
		}
		return updateMsg{u, gen}
	}
}

func (m *Model) startCapture() tea.Cmd {
	m.capChan = make(chan tea.Msg, 256)
	m.capDone = make(chan struct{})
	var ctx context.Context
	ctx, m.capCancel = context.WithCancel(context.Background())
	es, ch, done := m.cfg.Capture, m.capChan, m.capDone
	go func() {
		defer close(done)
		send := func(msg tea.Msg) {
			select {
			case ch <- msg:
			case <-ctx.Done():
			}
		}
		note, err := es.Stream(ctx, func(e event.Event) { send(capEventMsg(e)) })
		send(capDoneMsg{note, err})
	}()
	return waitCap(ch)
}

func waitCap(ch chan tea.Msg) tea.Cmd { return func() tea.Msg { return <-ch } }

func (m *Model) reclassify() {
	m.findings = m.cfg.Rules.Process(m.events, m.cfg.Baseline)
	m.sinceUI = 0
	if rs := m.rows(); m.cursor >= len(rs) {
		m.cursor = max(0, len(rs)-1)
	}
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case updateMsg:
		if msg.gen != m.gen {
			return m, nil // from a window the user already left
		}
		u := msg.u
		m.events = append(m.events, u.Events...)
		m.sinceUI += len(u.Events)
		if u.Err != nil {
			m.meta.Errors[u.Source] = u.Err
		}
		m.meta.Notes = append(m.meta.Notes, u.Notes...)
		for _, e := range u.Events {
			m.meta.Redactions += e.Redactions
		}
		if u.Done {
			delete(m.pending, u.Source)
		}
		if u.Done || m.sinceUI >= 1000 {
			m.reclassify()
		}
		return m, waitUpdate(m.updates, m.gen)
	case closedMsg:
		if msg.gen != m.gen {
			return m, nil
		}
		m.loading = false
		m.reclassify()
	case capEventMsg:
		e := event.Event(msg)
		m.tree.Add(e)
		if e.Kind == event.KindExit {
			if fl, ok := collect.Flash(m.tree, e); ok {
				m.events = append(m.events, fl)
				m.reclassify()
			}
		} else if e.Kind != event.KindExec {
			m.events = append(m.events, e)
			m.reclassify()
		}
		return m, waitCap(m.capChan)
	case capDoneMsg:
		m.capNote = msg.note
		if msg.err != nil {
			m.status = "capture stopped: " + msg.err.Error()
		}
	case statusMsg:
		m.status = msg.text
		if msg.reclassify {
			m.reclassify()
		}
	case windowMsg:
		return m, m.setWindow(msg.label, msg.since)
	case linesMsg:
		if m.view == msg.v {
			m.lines = msg.lines
		}
	case tea.KeyPressMsg:
		return m, m.key(msg.String())
	}
	return m, nil
}

func (m *Model) key(k string) tea.Cmd {
	if m.filtering {
		switch k {
		case "enter", "esc":
			m.filtering = false
		case "backspace":
			if m.filter != "" {
				m.filter = m.filter[:len(m.filter)-1]
			}
		default:
			if len([]rune(k)) == 1 {
				m.filter += k
			} else if k == "space" {
				m.filter += " "
			}
		}
		m.cursor, m.offset = 0, 0
		return nil
	}
	m.status = ""
	if k == "ctrl+c" {
		return m.quit()
	}
	if m.view != timelineView {
		return m.subKey(k)
	}
	rs := m.rows()
	switch k {
	case "q", "esc":
		return m.quit()
	case "up", "k":
		m.move(rs, -1)
	case "down", "j":
		m.move(rs, 1)
	case "pgup":
		m.move(rs, -m.bodyHeight())
	case "pgdown":
		m.move(rs, m.bodyHeight())
	case "home", "g":
		m.cursor = 0
	case "end", "G":
		m.cursor = max(0, len(rs)-1)
	case "n":
		m.jump(rs, 1)
	case "N":
		m.jump(rs, -1)
	case "enter":
		if m.current(rs) != nil {
			m.view, m.showRaw = cardView, false
		}
	case "s":
		m.meta.Floor = (m.meta.Floor + 1) % (event.Critical + 1)
		m.cursor, m.offset = 0, 0
	case "S":
		m.meta.All = !m.meta.All
		m.cursor, m.offset = 0, 0
	case "t":
		return m.cycleWindow()
	case "tab":
		m.group = (m.group + 1) % 3
		m.cursor, m.offset = 0, 0
	case "/":
		m.filtering, m.filter = true, ""
	case "a":
		return m.acknowledge(m.current(rs))
	case "R":
		return m.open(restartView, m.restartLines)
	case "A":
		return m.openAncestry(m.current(rs))
	case "c":
		return m.open(netView, m.netLines)
	case "e":
		m.openExport()
	case "?":
		m.view = helpView
	}
	return nil
}

func (m *Model) subKey(k string) tea.Cmd {
	switch k {
	case "q":
		return m.quit()
	case "esc", "backspace", "left", "h":
		m.view = timelineView
		return nil
	}
	switch m.view {
	case cardView:
		f := m.current(m.rows())
		switch k {
		case "r":
			m.showRaw = !m.showRaw
		case "a":
			return m.acknowledge(f)
		case "A":
			return m.openAncestry(f)
		case "R":
			return m.open(restartView, m.restartLines)
		case "e":
			m.openExport()
		}
	case netView:
		if k == "r" {
			return m.open(netView, m.netLines)
		}
	case exportView:
		switch k {
		case "w":
			return m.writeExport()
		case "y":
			return m.copyExport()
		}
	}
	return nil
}

func (m *Model) quit() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	if m.capCancel != nil {
		m.capCancel() // stops eslogger
	}
	return tea.Quit
}

// Close stops a running capture and waits (briefly) until eslogger has
// exited, so a --save file is complete before main closes it.
func (m *Model) Close() {
	if m.capCancel == nil {
		return
	}
	m.capCancel()
	select {
	case <-m.capDone:
	case <-time.After(3 * time.Second):
	}
}

func (m *Model) move(rs []row, d int) {
	if len(rs) == 0 {
		return
	}
	c := max(0, min(len(rs)-1, m.cursor+d))
	// step over headers in the direction of travel
	for c > 0 && c < len(rs)-1 && rs[c].f == nil {
		if d < 0 {
			c--
		} else {
			c++
		}
	}
	m.cursor = c
}

func (m *Model) jump(rs []row, d int) {
	for i := m.cursor + d; i >= 0 && i < len(rs); i += d {
		if rs[i].f != nil && rs[i].f.Level >= event.Medium {
			m.cursor = i
			return
		}
	}
	m.status = "no more rows at medium or above"
}

func (m *Model) current(rs []row) *rules.Finding {
	if m.cursor < 0 || m.cursor >= len(rs) {
		return nil
	}
	return rs[m.cursor].f
}

// cycleWindow moves to the next window. "since boot" needs the boot
// time, which is read in a command, not in Update.
func (m *Model) cycleWindow() tea.Cmd {
	m.windowIdx = (m.windowIdx + 1) % len(windows)
	w := windows[m.windowIdx]
	if w == "boot" {
		if m.meta.Replay {
			m.windowIdx = 0 // a replay has no boot; wrap to 5m
			return m.setWindow(windows[0], time.Now().Add(-5*time.Minute))
		}
		return func() tea.Msg {
			boots, err := darwin.BootTimes(context.Background())
			if err != nil || len(boots) == 0 {
				return statusMsg{text: "cannot read the boot time"}
			}
			return windowMsg{label: "since boot", since: boots[0]}
		}
	}
	d, _ := time.ParseDuration(w)
	return m.setWindow(w, time.Now().Add(-d))
}

func (m *Model) setWindow(label string, since time.Time) tea.Cmd {
	m.meta.Since, m.meta.Window = since, label
	return m.startCollect()
}

// acknowledge writes the baseline in a command and reclassifies when done.
func (m *Model) acknowledge(f *rules.Finding) tea.Cmd {
	if f == nil {
		return nil
	}
	key := f.Event.Subject.Key()
	if key == "" {
		m.status = "this row has no stable subject to remember"
		return nil
	}
	b, label := m.cfg.Baseline, m.cfg.Redactor.String(f.Event.Subject.Label())
	return func() tea.Msg {
		if err := b.MarkKnown(key); err != nil {
			return statusMsg{text: "not marked: " + err.Error()}
		}
		return statusMsg{text: "marked " + label + " as known (stored as a salted hash)", reclassify: true}
	}
}

// open switches to a view whose lines load in the background.
func (m *Model) open(v view, load func(context.Context) []string) tea.Cmd {
	m.view, m.lines = v, []string{"Loading…"}
	ctx := context.Background() // views outlive a window change
	return func() tea.Msg { return linesMsg{v, load(ctx)} }
}

func (m *Model) restartLines(ctx context.Context) []string {
	if m.cfg.Restart == nil {
		return []string{"No restart evidence source."}
	}
	ev, err := m.cfg.Restart(ctx)
	if err != nil {
		return []string{"Cannot build the restart verdict: " + err.Error()}
	}
	return redactAll(m.cfg.Redactor, report.RestartLines(restart.Decide(ev), ev))
}

func (m *Model) netLines(ctx context.Context) []string {
	if m.cfg.NoNet != "" {
		return []string{m.cfg.NoNet, "", darwin.NetLimit}
	}
	conns, traffic, err := darwin.LiveNet(ctx)
	if err != nil {
		return []string{"lsof failed: " + err.Error()}
	}
	out := []string{"Live connections of your processes, now. " + darwin.NetLimit, ""}
	for _, c := range conns {
		if c.State == "ESTABLISHED" {
			out = append(out, fmt.Sprintf("%-18s %6d  %-4s %s", c.Command, c.PID, c.Proto, m.cfg.Redactor.String(c.Name)))
		}
	}
	out = append(out, "", "Traffic since each process started (nettop), busiest first:")
	for i, t := range traffic {
		if i == 12 {
			break
		}
		out = append(out, fmt.Sprintf("%-28s %6d  in %9s  out %9s", t.Process, t.PID, human(t.BytesIn), human(t.BytesOut)))
	}
	return append(out, "", "r refresh")
}

func (m *Model) openAncestry(f *rules.Finding) tea.Cmd {
	if f == nil || f.Event.Subject.PID == 0 {
		m.status = "this row has no process id"
		return nil
	}
	pid := f.Event.Subject.PID
	if m.tree != nil {
		m.view = ancestryView
		m.lines = report.AncestryLines(m.tree, pid, m.cfg.Redactor)
		return nil
	}
	red := m.cfg.Redactor
	return m.open(ancestryView, func(ctx context.Context) []string {
		t, err := darwin.LiveTree(ctx)
		if err != nil {
			return []string{"ps failed: " + err.Error()}
		}
		lines := report.AncestryLines(t, pid, red)
		return append(lines, "", "Without capture this is today's process table: if the pid was reused, the chain belongs to another process.",
			"Full history with command lines: sudo lately capture")
	})
}

func (m *Model) openExport() {
	var b strings.Builder
	report.Markdown(&b, m.findings, m.meta, m.cfg.Redactor)
	m.exportText = b.String()
	m.view = exportView
	m.lines = strings.Split(m.exportText, "\n")
}

func (m *Model) writeExport() tea.Cmd {
	text, red := m.exportText, m.cfg.Redactor
	return func() tea.Msg {
		name := "lately-" + time.Now().Format("20060102-150405") + ".md"
		if err := os.WriteFile(name, []byte(text), 0o600); err != nil {
			return statusMsg{text: "not saved: " + err.Error()}
		}
		abs, _ := filepath.Abs(name)
		return statusMsg{text: "saved " + red.String(abs)}
	}
}

func (m *Model) copyExport() tea.Cmd {
	text := m.exportText
	return func() tea.Msg {
		cmd := exec.Command("/usr/bin/pbcopy")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			return statusMsg{text: "copy failed: " + err.Error()}
		}
		return statusMsg{text: "copied the redacted Markdown to the clipboard"}
	}
}

// rows applies the floor, filter and grouping.
func (m *Model) rows() []row {
	vis := report.Visible(m.findings, m.meta)
	if m.filter != "" {
		q := strings.ToLower(m.filter)
		var keep []*rules.Finding
		for _, f := range vis {
			if strings.Contains(strings.ToLower(f.Title+" "+f.Rule.Category+" "+f.Rule.ID+" "+f.Event.Subject.Label()), q) {
				keep = append(keep, f)
			}
		}
		vis = keep
	}
	if m.group == byTime {
		out := make([]row, len(vis))
		for i, f := range vis {
			out[i] = row{f: f}
		}
		return out
	}
	var order []string
	groups := map[string][]*rules.Finding{}
	for _, f := range vis {
		k := f.Rule.Category
		if m.group == bySubject {
			k = m.cfg.Redactor.String(f.Event.Subject.Label())
		}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], f)
	}
	var out []row
	for _, k := range order {
		out = append(out, row{header: fmt.Sprintf("%s · %d", k, len(groups[k]))})
		for _, f := range groups[k] {
			out = append(out, row{f: f})
		}
	}
	return out
}

func redactAll(r *redact.Redactor, ss []string) []string {
	for i := range ss {
		ss[i] = r.String(ss[i])
	}
	return ss
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
