package ui

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/report"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// recSource serves fixed events and records every span it is asked for.
type recSource struct {
	id     string
	events []event.Event
	mu     sync.Mutex
	spans  [][2]time.Time
}

func (s *recSource) ID() string        { return s.id }
func (s *recSource) Tier() source.Tier { return source.TierUser }
func (s *recSource) Probe(context.Context) source.Capability {
	return source.Capability{Available: true}
}
func (s *recSource) History(_ context.Context, since, until time.Time, emit func(event.Event)) error {
	s.mu.Lock()
	s.spans = append(s.spans, [2]time.Time{since, until})
	s.mu.Unlock()
	for _, e := range s.events {
		if !e.TS.Before(since) && !e.TS.After(until) {
			emit(e)
		}
	}
	return nil
}

func (s *recSource) calls() [][2]time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][2]time.Time(nil), s.spans...)
}

func crash(name string, ts time.Time) event.Event {
	return event.Event{TS: ts, Source: "reports", Kind: "crash", Subject: event.Subject{Name: name},
		Fields: map[string]string{"report_kind": "crash", "file": name + ts.Format("150405") + ".ips"}}
}

func liveModel(t *testing.T, src *recSource) *Model {
	t.Helper()
	now := time.Now()
	m := New(Config{Meta: report.Meta{Since: now.Add(-15 * time.Minute), Until: now, Window: "15m", Floor: event.Medium},
		Rules: rules.Builtin(), Baseline: baseline.Disable(), Sources: []source.Source{src}})
	m.width, m.height = 120, 30
	drive(m, m.Init())
	return m
}

func TestWindowLadder(t *testing.T) {
	now := time.Now()
	src := &recSource{id: "reports", events: []event.Event{crash("Recent", now.Add(-5*time.Minute)), crash("Older", now.Add(-50*time.Minute))}}
	m := liveModel(t, src)
	if len(m.findings) != 1 {
		t.Fatalf("15m should hold one crash, got %d", len(m.findings))
	}
	drive(m, m.key("t"))
	if m.meta.Window != "30m" {
		t.Fatalf("t from 15m went to %s", m.meta.Window)
	}
	drive(m, m.key("t"))
	if m.meta.Window != "1h" || len(m.findings) != 2 {
		t.Fatalf("t t should reach 1h and the older crash: %s, %d findings", m.meta.Window, len(m.findings))
	}
	// Widening read only the older spans, never the 15 minutes again.
	calls := src.calls()
	if len(calls) != 3 {
		t.Fatalf("want 3 reads (15m, then two older spans), got %v", calls)
	}
	for _, c := range calls[1:] {
		if c[1].After(now.Add(-14 * time.Minute)) {
			t.Errorf("a wider window re-read recent time: %v", c)
		}
	}
	// Narrowing reads nothing and drops the older crash from view.
	cmd := m.key("T")
	if cmd != nil || len(src.calls()) != 3 || m.meta.Window != "30m" || len(m.findings) != 1 {
		t.Errorf("T should only filter: window %s, %d findings, %d reads", m.meta.Window, len(m.findings), len(src.calls()))
	}
	drive(m, m.key("t"))
	if len(src.calls()) != 3 || len(m.findings) != 2 {
		t.Error("going back out to 1h again must not read anything")
	}
	if !strings.Contains(strings.Join(strings.Fields(ansi.Strip(m.statusLine())), " "), "window 5m 15m 30m 1h 2h") {
		t.Errorf("ladder not shown: %q", ansi.Strip(m.statusLine()))
	}
	for range len(ladder) {
		m.key("T")
	}
	if m.meta.Window != "5m" || !strings.Contains(m.status, "narrowest") {
		t.Errorf("T past the end: %s %q", m.meta.Window, m.status)
	}
}

type fakeFollower struct{ ch chan event.Event }

func (f *fakeFollower) ID() string { return "live" }
func (f *fakeFollower) Follow(ctx context.Context, emit func(event.Event)) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case e := <-f.ch:
			emit(e)
		}
	}
}

func TestFollow(t *testing.T) {
	now := time.Now()
	src := &recSource{id: "reports", events: []event.Event{crash("Old", now.Add(-5*time.Minute))}}
	m := liveModel(t, src)
	ff := &fakeFollower{ch: make(chan event.Event, 4)}
	m.cfg.Followers = func() []source.Follower { return []source.Follower{ff} }
	cmd := m.key("f")
	if !m.follow || cmd == nil {
		t.Fatal("f should start following")
	}
	ff.ch <- crash("Fresh", time.Now())
	pump(t, m, cmd, func() bool { return len(m.findings) == 2 })
	f := m.current(m.rows())
	if f == nil || !strings.Contains(f.Title, "Fresh") {
		t.Errorf("the cursor should sit on the newest row while following: %v", f)
	}
	if !strings.Contains(m.status, "new HIGH") && !strings.Contains(m.status, "following") {
		t.Errorf("status: %q", m.status)
	}
	out := ansi.Strip(m.render())
	if !strings.Contains(out, "● live") || !strings.Contains(out, "now ●") || !strings.Contains(out, "f pause") {
		t.Errorf("live header missing:\n%s", out)
	}
	m.key("f")
	if m.follow || m.fcancel != nil {
		t.Error("f again should pause")
	}
	m.cfg.Followers = nil
	m.cfg.NoFollow = "this sample has no live.ndjson"
	m.key("f")
	if m.follow || !strings.Contains(m.status, "not available") {
		t.Errorf("follow without followers: %q", m.status)
	}
}

// pump runs the follow commands until done holds (or fails after 2 s).
func pump(t *testing.T, m *Model, cmd tea.Cmd, done func() bool) {
	t.Helper()
	q := make(chan tea.Msg, 64)
	deadline := time.After(2 * time.Second)
	go runCmd(cmd, q)
	for !done() {
		select {
		case msg := <-q:
			_, next := m.Update(msg)
			go runCmd(next, q)
		case <-deadline:
			t.Fatal("timed out waiting for follow")
		}
	}
}

func TestCardRelatedNavigation(t *testing.T) {
	now := time.Now()
	src := &recSource{id: "reports", events: []event.Event{
		crash("Foo", now.Add(-12*time.Minute)), crash("Foo", now.Add(-1*time.Minute)), crash("Bar", now.Add(-50*time.Second)),
	}}
	m := liveModel(t, src)
	rs := m.rows()
	for i, r := range rs {
		if r.f != nil && r.f.Event.Subject.Name == "Bar" {
			m.cursor = i
		}
	}
	if !strings.Contains(ansi.Strip(m.render()), "related: 1 around then") {
		t.Errorf("detail pane should summarise relations:\n%s", ansi.Strip(m.render()))
	}
	m.key("enter")
	card := ansi.Strip(m.render())
	for _, want := range []string{"ACTIVITY", "RELATED · 1 around then", "-10s  around then", "Foo crashed ×2", "this · 1 event(s) of Bar", "▲"} {
		if !strings.Contains(card, want) {
			t.Errorf("card lacks %q:\n%s", want, card)
		}
	}
	m.key("enter") // open the first related row
	if len(m.cardStack) != 2 || !strings.Contains(ansi.Strip(m.render()), "card 2 · esc back") {
		t.Fatalf("enter on a related row should push a card: %d", len(m.cardStack))
	}
	if c := ansi.Strip(m.render()); !strings.Contains(c, "Foo crashed ×2") || !strings.Contains(c, "2 event(s) of Foo") {
		t.Errorf("second card should be the grouped Foo row:\n%s", c)
	}
	m.key("esc")
	if m.view != cardView || len(m.cardStack) != 1 {
		t.Error("esc should return to the first card")
	}
	m.key("esc")
	if m.view != timelineView {
		t.Error("esc from the first card should return to the timeline")
	}
	for _, w := range []int{50, 80, 120, 200} {
		m.width, m.height = w, 14
		m.key("enter")
		for _, l := range strings.Split(m.render(), "\n") {
			if ansi.StringWidth(l) > max(w, 50) {
				t.Errorf("width %d: card line overflows: %q", w, ansi.Strip(l))
			}
		}
		m.key("esc")
	}
}

func TestCardSurvivesNarrowing(t *testing.T) {
	now := time.Now()
	m := liveModel(t, &recSource{id: "reports", events: []event.Event{crash("Foo", now.Add(-10*time.Minute))}})
	m.key("enter")
	m.cardStack[0].f = ref{id: "gone", rule: "none"}
	if !strings.Contains(m.render(), "no longer in the window") {
		t.Error("a card whose finding left the window should say so")
	}
}

func TestStripAndDelta(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s := ansi.Strip(strip([]point{{t0.Add(time.Minute), event.High}}, t0, t0.Add(10*time.Minute), 10, t0.Add(9*time.Minute)))
	if ansi.StringWidth(s) != 10 || []rune(s)[1] == '·' || []rune(s)[9] != '│' {
		t.Errorf("strip %q", s)
	}
	for d, want := range map[time.Duration]string{-130 * time.Second: "-2m10s", 4 * time.Second: "+4s", 185 * time.Minute: "+3h05m", -50 * time.Hour: "-2d"} {
		if got := delta(d); got != want {
			t.Errorf("delta(%v) = %s, want %s", d, got, want)
		}
	}
}

// runCmd runs a command (and every command in a batch) and queues the
// resulting messages.
func runCmd(c tea.Cmd, q chan<- tea.Msg) {
	if c == nil {
		return
	}
	msg := c()
	if b, ok := msg.(tea.BatchMsg); ok {
		for _, c := range b {
			go runCmd(c, q)
		}
		return
	}
	if msg != nil {
		q <- msg
	}
}

// Regressions from review.

func TestIdleThenNarrowReadsTheGap(t *testing.T) {
	now := time.Now()
	src := &recSource{id: "reports", events: []event.Event{crash("Late", now.Add(-2*time.Minute))}}
	m := liveModel(t, src)
	// Pretend the TUI was opened 20 minutes ago and left alone.
	m.haveUntil, m.meta.Until = now.Add(-20*time.Minute), now.Add(-20*time.Minute)
	m.haveSince, m.meta.Since = now.Add(-35*time.Minute), now.Add(-35*time.Minute)
	m.all, m.seen, m.findings = nil, map[string]bool{}, nil
	m.reclassify()
	drive(m, m.key("T"))
	if !m.meta.Since.Before(m.meta.Until) || len(m.findings) != 1 {
		t.Errorf("narrowing after idling must read up to now: since %v until %v, %d findings", m.meta.Since, m.meta.Until, len(m.findings))
	}
	// t twice before the first read finishes still covers the gap.
	m.haveUntil = now.Add(-20 * time.Minute)
	m.all, m.seen, m.findings = nil, map[string]bool{}, nil
	m.key("t")
	drive(m, m.key("t"))
	if len(m.findings) != 1 {
		t.Errorf("t t lost the span since the last read: %d findings", len(m.findings))
	}
}

func TestFollowingWindowGrows(t *testing.T) {
	m := liveModel(t, &recSource{id: "reports"})
	m.follow, m.meta.Since = true, time.Now().Add(-75*time.Minute)
	if m.windowDur() < time.Hour {
		t.Errorf("while following the window is since its start: %v", m.windowDur())
	}
	m.follow = false
}

func TestFollowGapOverlapsTheStream(t *testing.T) {
	src := &recSource{id: "reports"}
	m := liveModel(t, src)
	ff := &fakeFollower{ch: make(chan event.Event, 1)}
	m.cfg.Followers = func() []source.Follower { return []source.Follower{ff} }
	m.key("f") // even right after a load
	deadline := time.Now().Add(time.Second)
	for len(src.calls()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	calls := src.calls()
	if len(calls) < 2 || !calls[len(calls)-1][1].After(m.fsince.Add(time.Second)) {
		t.Errorf("gap read should end past the stream's start: %v (follow at %v)", calls, m.fsince)
	}
	m.Close()
	if m.follow {
		t.Error("Close must stop follow")
	}
}

func TestRefSurvivesGroupHeadChange(t *testing.T) {
	now := time.Now()
	src := &recSource{id: "reports", events: []event.Event{crash("Foo", now.Add(-14*time.Minute)), crash("Foo", now.Add(-20*time.Minute))}}
	m := liveModel(t, src)
	m.key("enter")
	before := m.cardFinding()
	drive(m, m.setWindow("30m", now.Add(-30*time.Minute))) // the -20m crash becomes the group head, so the ID changes
	after := m.cardFinding()
	if before == nil || after == nil || after.Count != 2 || after.ID == before.ID {
		t.Fatalf("card lost its finding when the group grew: %v → %v", before, after)
	}
}

func TestCapturedEventsSurviveReload(t *testing.T) {
	m := liveModel(t, &recSource{id: "reports"})
	m.tree = ancestry.New("test")
	m.Update(capEventMsg(event.Event{TS: time.Now(), Source: "eslogger", Kind: event.KindAuth, Subject: event.Subject{Name: "sudo"},
		Fields: map[string]string{"method": "sudo", "success": "no"}}))
	n := len(m.all)
	drive(m, m.key("r"))
	if len(m.all) != n {
		t.Errorf("reload dropped captured events: %d → %d", n, len(m.all))
	}
}
