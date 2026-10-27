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
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/collect"
	"github.com/Matthew-Eucaristo/lately/internal/darwin"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/redact"
	"github.com/Matthew-Eucaristo/lately/internal/relate"
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
	// Followers builds the live sources for follow mode (f). When nil,
	// NoFollow says why follow is not available.
	Followers func() []source.Follower
	NoFollow  string
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

// ladder is the window steps t (older) and T (newer) walk through.
var ladder = []string{"5m", "15m", "30m", "1h", "2h", "3h", "6h", "12h", "1d", "2d", "3d", "7d"}

func ladderDur(label string) time.Duration {
	if n, ok := strings.CutSuffix(label, "d"); ok {
		d, _ := strconv.Atoi(n)
		return time.Duration(d) * 24 * time.Hour
	}
	d, _ := time.ParseDuration(label)
	return d
}

// followFlush batches live events; followTick redraws the live clock and
// reclassifies at most this often.
const (
	followFlush = 300 * time.Millisecond
	followTick  = time.Second
	freshFor    = 15 * time.Second // a live row stays highlighted this long
	// A window change also reads what happened since the last completed
	// read once that is older than this (not after every slow load: pmset
	// alone costs 5 s).
	catchUp = time.Minute
)

type (
	updateMsg struct {
		u   collect.Update
		gen int
	}
	closedMsg struct{ gen int }
	followMsg struct {
		u   collect.Update
		gen int
	}
	followClosedMsg struct{ gen int }
	tickMsg         struct{ gen int }
	linesMsg        struct {
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

	ctx       context.Context
	cancel    context.CancelFunc
	updates   <-chan collect.Update
	gen       int            // collection generation; stale updates are ignored
	pending   map[string]int // jobs still running per source
	loading   bool
	extending bool // the running load only widens the window
	sinceUI   int  // events since the last reclassify
	started   time.Time

	// all holds every event read so far, deduplicated, also those older
	// than the window: T (newer) only filters, so t (older) again is free.
	all       []event.Event
	seen      map[string]bool
	haveSince time.Time       // everything since then has been read …
	haveUntil time.Time       // … up to then (moved only when a load completes)
	loadUntil time.Time       // what the running load reads up to
	keep      []event.Event   // live events no history read can bring back
	loaded    map[string]bool // sources read over that span
	findings  []*rules.Finding
	ver       int // bumped on every reclassify

	follow    bool
	fcancel   context.CancelFunc
	fupdates  <-chan collect.Update
	fgen      int
	fdone     <-chan struct{} // closed once every follower has returned
	fsince    time.Time
	dirty     bool
	alerted   map[string]bool
	showSteps bool // show the window ladder on the status line

	cardStack []cardPos // the card on top is shown
	cardSel   int       // selected related row
	cardOff   int
	relKey    string // cache key for related()
	rel       []relate.Link

	view      view
	group     groupBy
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
	m := &Model{cfg: cfg, meta: cfg.Meta, width: 100, height: 30, pending: map[string]int{}, alerted: map[string]bool{},
		seen: map[string]bool{}, loaded: map[string]bool{}, haveSince: cfg.Meta.Since, haveUntil: cfg.Meta.Until}
	if m.meta.Errors == nil {
		m.meta.Errors = map[string]error{}
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

// startCollect reads the whole window again, snapshot included.
func (m *Model) startCollect() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	m.all, m.seen, m.findings, m.cursor, m.offset = nil, map[string]bool{}, nil, 0, 0
	m.meta.Until = time.Now()
	if m.cfg.SourcesFor != nil {
		m.cfg.Sources = m.cfg.SourcesFor(m.meta.Until.Sub(m.meta.Since))
	}
	m.meta.Errors = map[string]error{}
	m.meta.Notes = nil
	m.meta.Redactions = 0
	m.pending = map[string]int{}
	m.haveSince, m.loaded, m.loadUntil = m.meta.Since, map[string]bool{}, m.meta.Until
	m.add(m.keep) // captured and followed events cannot be read again
	for _, s := range m.cfg.Sources {
		m.pending[s.ID()]++
		m.loaded[s.ID()] = true
	}
	m.loading, m.extending, m.started = true, false, time.Now()
	m.gen++
	m.updates = collect.Stream(m.ctx, collect.Options{Since: m.meta.Since, Until: m.meta.Until,
		Sources: m.cfg.Sources, Baseline: m.cfg.Baseline})
	return waitUpdate(m.updates, m.gen)
}

// extend reads only what a window change adds: the older span for the
// sources already read, the whole window for sources the wider window
// brings in (pmset from an hour), and, when not following, the time since
// the last completed read. With nothing to read it starts no load.
func (m *Model) extend() tea.Cmd {
	if m.cancel != nil {
		m.cancel()
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	now := time.Now()
	var old, added []source.Source
	srcs := m.cfg.Sources
	if m.cfg.SourcesFor != nil {
		srcs = m.cfg.SourcesFor(now.Sub(m.meta.Since))
	}
	for _, s := range srcs {
		if m.loaded[s.ID()] {
			old = append(old, s)
		} else {
			added = append(added, s)
		}
	}
	m.cfg.Sources = srcs
	m.pending = map[string]int{}
	var chs []<-chan collect.Update
	job := func(since, until time.Time, ss []source.Source) {
		if len(ss) == 0 || !since.Before(until) {
			return
		}
		for _, s := range ss {
			m.pending[s.ID()]++
		}
		chs = append(chs, collect.Stream(m.ctx, collect.Options{Since: since, Until: until, Sources: ss}))
	}
	job(m.meta.Since, m.haveSince, old)
	job(m.meta.Since, now, added)
	m.loadUntil = m.haveUntil
	if !m.follow && now.Sub(m.haveUntil) > catchUp {
		job(m.haveUntil, now, old)
		m.loadUntil = now
	}
	m.meta.Until = now
	m.gen++
	if len(chs) == 0 {
		m.loading, m.extending = false, false
		return nil
	}
	m.loading, m.extending, m.started = true, true, time.Now()
	m.updates = collect.Merge(m.ctx, chs...)
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

// reclassify rebuilds the findings from the events inside the window and
// keeps the cursor on the same finding (or on the newest while following).
func (m *Model) reclassify() {
	rs := m.rows()
	var cur *ref
	top := m.cursor <= firstRow(rs)
	if f := m.current(rs); f != nil {
		r := refOf(f)
		cur = &r
	}
	var evs []event.Event
	for _, e := range m.all {
		if !e.TS.Before(m.meta.Since) {
			evs = append(evs, e)
		}
	}
	m.findings = m.cfg.Rules.Process(evs, m.cfg.Baseline)
	m.ver++
	m.sinceUI, m.dirty = 0, false
	rs = m.rows()
	switch {
	case m.follow && top:
		m.cursor = firstRow(rs)
	case cur != nil:
		if f := cur.find(m.findings); f != nil {
			for i, r := range rs {
				if r.f == f {
					m.cursor = i
				}
			}
		}
	}
	if m.cursor >= len(rs) {
		m.cursor = max(0, len(rs)-1)
	}
	if m.follow {
		m.alert()
	}
}

func firstRow(rs []row) int {
	for i, r := range rs {
		if r.f != nil {
			return i
		}
	}
	return 0
}

// alert puts a newly arrived HIGH or CRIT row on the status line.
func (m *Model) alert() {
	for _, f := range report.Visible(m.findings, m.meta) {
		if f.Level < event.High || f.Last.Before(m.fsince) || m.alerted[f.ID+f.Last.String()] {
			continue
		}
		m.alerted[f.ID+f.Last.String()] = true
		m.status = fmt.Sprintf("%s new %s at %s: %s", f.Level.Glyph(), f.Level.Short(), f.Last.Local().Format("15:04:05"), m.cfg.Redactor.String(f.Title))
	}
}

// add keeps one copy of each event and reports how many were new.
func (m *Model) add(evs []event.Event) int {
	n := 0
	for _, e := range evs {
		k := collect.Key(e)
		if m.seen[k] {
			continue
		}
		m.seen[k] = true
		m.all = append(m.all, e)
		m.meta.Redactions += e.Redactions
		n++
	}
	return n
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
		m.sinceUI += m.add(u.Events)
		if u.Err != nil {
			m.meta.Errors[u.Source] = u.Err
		}
		m.meta.Notes = append(m.meta.Notes, u.Notes...)
		if u.Done && m.pending[u.Source] > 0 {
			if m.pending[u.Source]--; m.pending[u.Source] == 0 {
				delete(m.pending, u.Source)
			}
		}
		if u.Done || m.sinceUI >= 1000 {
			m.reclassify()
		}
		return m, waitUpdate(m.updates, m.gen)
	case closedMsg:
		if msg.gen != m.gen {
			return m, nil
		}
		if m.extending {
			for _, s := range m.cfg.Sources {
				m.loaded[s.ID()] = true
			}
		}
		if m.meta.Since.Before(m.haveSince) {
			m.haveSince = m.meta.Since
		}
		if m.loadUntil.After(m.haveUntil) {
			m.haveUntil = m.loadUntil
		}
		m.loading, m.extending = false, false
		m.reclassify()
	case followMsg:
		if msg.gen != m.fgen {
			return m, nil
		}
		if m.add(msg.u.Events) > 0 {
			m.dirty = true
		}
		m.keep = append(m.keep, msg.u.Events...)
		if msg.u.Err != nil {
			m.meta.Errors[msg.u.Source] = msg.u.Err
		}
		return m, waitFollow(m.fupdates, m.fgen)
	case followClosedMsg:
		if msg.gen == m.fgen && m.follow {
			m.stopFollow()
			m.status = "follow stopped: every live source ended (? shows why)"
		}
	case tickMsg:
		if msg.gen != m.fgen || !m.follow {
			return m, nil
		}
		m.meta.Until = time.Now()
		if m.dirty {
			m.reclassify()
		}
		return m, tick(m.fgen)
	case capEventMsg:
		e := event.Event(msg)
		m.tree.Add(e)
		if e.Kind == event.KindExit {
			if fl, ok := collect.Flash(m.tree, e); ok && m.add([]event.Event{fl}) > 0 {
				m.keep = append(m.keep, fl)
				m.reclassify()
			}
		} else if e.Kind != event.KindExec && m.add([]event.Event{e}) > 0 {
			m.keep = append(m.keep, e)
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
		if f := m.current(rs); f != nil {
			m.openCard(f, false)
		}
	case "s":
		m.meta.Floor = (m.meta.Floor + 1) % (event.Critical + 1)
		m.cursor, m.offset = 0, 0
	case "S":
		m.meta.All = !m.meta.All
		m.cursor, m.offset = 0, 0
	case "t":
		return m.step(1)
	case "T":
		return m.step(-1)
	case "B":
		return m.sinceBoot()
	case "f":
		return m.toggleFollow()
	case "r":
		m.showSteps = false
		return m.startCollect()
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
	if k == "q" {
		return m.quit()
	}
	if m.view == cardView {
		return m.cardKey(k)
	}
	switch k {
	case "esc", "backspace", "left", "h":
		m.view = timelineView
		return nil
	}
	switch m.view {
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
	m.stopFollow()
	if m.capCancel != nil {
		m.capCancel() // stops eslogger
	}
	return tea.Quit
}

// Close stops loads, follow and a running capture, and waits (briefly)
// until log stream and eslogger have exited, so no child outlives lately
// and a --save file is complete before main closes it.
func (m *Model) Close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.stopFollow()
	if m.fdone != nil {
		select { // log stream children must not outlive lately
		case <-m.fdone:
		case <-time.After(3 * time.Second):
		}
	}
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

// step moves one rung along the ladder: +1 reaches further back, -1
// comes closer to now. A window that is not on the ladder (since boot,
// --since 45m) steps to the nearest rung in that direction.
func (m *Model) step(dir int) tea.Cmd {
	cur := m.windowDur()
	pick := -1
	for i, l := range ladder {
		d := ladderDur(l)
		if dir > 0 && d > cur && pick < 0 {
			pick = i
		}
		if dir < 0 && d < cur {
			pick = i
		}
	}
	if pick < 0 {
		m.showSteps = true
		if dir > 0 {
			m.status = "already the widest step · B shows everything since boot"
		} else {
			m.status = "already the narrowest step"
		}
		return nil
	}
	l := ladder[pick]
	return m.setWindow(l, time.Now().Add(-ladderDur(l)))
}

// windowDur is the window's length as the ladder sees it.
func (m *Model) windowDur() time.Duration {
	if d := ladderDur(m.meta.Window); d > 0 && !m.follow { // following keeps the start, so the window grows
		return d
	}
	return time.Since(m.meta.Since)
}

// sinceBoot reads the boot time in a command, not in Update.
func (m *Model) sinceBoot() tea.Cmd {
	if m.meta.Replay {
		m.status = "sample data has no boot; t and T change the window"
		return nil
	}
	return func() tea.Msg {
		boots, err := darwin.BootTimes(context.Background())
		if err != nil || len(boots) == 0 {
			return statusMsg{text: "cannot read the boot time"}
		}
		return windowMsg{label: "since boot", since: boots[0]}
	}
}

// setWindow narrows by filtering the kept events and widens by reading
// only the older part (plus what happened since the last read). A window change during the first
// load restarts that load, which still has the snapshot to take.
func (m *Model) setWindow(label string, since time.Time) tea.Cmd {
	m.meta.Since, m.meta.Window, m.showSteps = since, label, true
	if m.loading && !m.extending {
		return m.startCollect()
	}
	cmd := m.extend()
	m.reclassify()
	return cmd
}

// toggleFollow starts or stops follow mode. Starting also reads what
// happened since the last read, so nothing falls between history and the
// live feed (repeats are dropped).
func (m *Model) toggleFollow() tea.Cmd {
	if m.follow {
		m.stopFollow()
		m.status = "follow paused · f resumes"
		return nil
	}
	if m.cfg.Followers == nil {
		m.status = "follow is not available: " + m.cfg.NoFollow
		return nil
	}
	fs := m.cfg.Followers()
	if len(fs) == 0 {
		m.status = "follow is not available: no live source"
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.follow, m.fcancel, m.fsince = true, cancel, time.Now()
	m.fgen++
	live, done := collect.Follow(ctx, fs, followFlush)
	m.fdone = done
	// What fell between the last completed read and the moment log stream
	// attaches; `log show --end` is cut to whole seconds, so overlap by 2 s
	// and let Key drop the repeats.
	var srcs []source.Source
	for _, s := range m.cfg.Sources {
		if m.loaded[s.ID()] {
			srcs = append(srcs, s)
		}
	}
	gap := collect.Stream(ctx, collect.Options{Since: m.haveUntil, Until: m.fsince.Add(2 * time.Second), Sources: srcs})
	m.fupdates = collect.Merge(ctx, live, gap)
	m.cursor = firstRow(m.rows())
	m.status = fmt.Sprintf("following %d live source(s) · new rows appear at the top · f pauses", len(fs))
	return tea.Batch(waitFollow(m.fupdates, m.fgen), tick(m.fgen))
}

func (m *Model) stopFollow() {
	if m.fcancel != nil {
		m.fcancel()
		m.fcancel = nil
		m.haveUntil = time.Now() // followed up to now (pmset and boots excepted)
	}
	m.follow = false
	m.fgen++
}

func waitFollow(ch <-chan collect.Update, gen int) tea.Cmd {
	return func() tea.Msg {
		u, ok := <-ch
		if !ok {
			return followClosedMsg{gen}
		}
		return followMsg{u, gen}
	}
}

func tick(gen int) tea.Cmd {
	return tea.Tick(followTick, func(time.Time) tea.Msg { return tickMsg{gen} })
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

// ref finds a finding again after reclassify. The ID hashes the group's
// first event, which changes when a wider window brings in an earlier
// occurrence or a narrower one drops it, so it falls back to the same rule
// and subject with an occurrence close to the remembered one.
type ref struct {
	id, rule, key string
	ts            time.Time
}

func refOf(f *rules.Finding) ref {
	return ref{f.ID, f.Rule.ID, f.Event.Subject.Key(), f.Event.TS}
}

func (r ref) find(fs []*rules.Finding) *rules.Finding {
	var best *rules.Finding
	bestD := 10 * time.Minute
	for _, f := range fs {
		if f.ID == r.id {
			return f
		}
		if f.Rule.ID != r.rule || f.Event.Subject.Key() != r.key {
			continue
		}
		for _, t := range f.Times {
			if d := t.Sub(r.ts).Abs(); d <= bestD {
				best, bestD = f, d
			}
		}
	}
	return best
}
