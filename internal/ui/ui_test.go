package ui

import (
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/collect"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/report"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
)

func model(t *testing.T) *Model {
	t.Helper()
	now := time.Now()
	m := New(Config{Meta: report.Meta{Since: now.Add(-15 * time.Minute), Until: now, Window: "15m", Tier: "user", Floor: event.Medium,
		Errors: map[string]error{}}, Rules: rules.Builtin(), Baseline: baseline.Disable()})
	m.width, m.height = 120, 30
	m.Update(updateMsg{gen: m.gen, u: collect.Update{Source: "test", Done: true, Events: []event.Event{
		{TS: now.Add(-2 * time.Minute), Kind: "crash", Source: "reports", Subject: event.Subject{Name: "Foo"}, Fields: map[string]string{"report_kind": "crash"}},
		{TS: now.Add(-time.Minute), Kind: "persist", Source: "persist", Subject: event.Subject{Name: "com.foo.agent"}, Fields: map[string]string{"persist": "launch_agent", "change": "added"}},
	}}})
	m.Update(closedMsg{m.gen})
	return m
}

func press(m *Model, keys ...string) {
	for _, k := range keys {
		m.key(k)
	}
}

func TestTimelineAndCard(t *testing.T) {
	m := model(t)
	out := m.render()
	for _, want := range []string{"Launch agent added: com.foo.agent", "Foo crashed", "sudo lately capture", "▲ 1"} {
		if !strings.Contains(out, want) {
			t.Errorf("timeline lacks %q:\n%s", want, out)
		}
	}
	press(m, "enter")
	card := m.render()
	for _, want := range []string{"WHAT", "WHO", "WHY", "MATTERS", "DO", "RAW", "SOURCE", "T1543.001"} {
		if !strings.Contains(card, want) {
			t.Errorf("card lacks %q:\n%s", want, card)
		}
	}
	press(m, "esc", "s", "s")
	if m.meta.Floor != event.Critical || !strings.Contains(m.render(), "Nothing at critical") {
		t.Errorf("floor cycle: %v", m.meta.Floor)
	}
	press(m, "s", "tab", "?", "esc", "e")
	if m.view != exportView || !strings.Contains(m.exportText, "| Time |") {
		t.Error("export preview missing")
	}
}

func TestStaleUpdatesIgnored(t *testing.T) {
	m := model(t)
	n := len(m.all)
	m.Update(updateMsg{gen: m.gen - 1, u: collect.Update{Source: "old", Events: []event.Event{{Kind: "crash"}}}})
	if len(m.all) != n {
		t.Error("an update from an old window was applied")
	}
}

func TestQuit(t *testing.T) {
	m := model(t)
	if cmd := m.key("q"); cmd == nil {
		t.Fatal("q should quit")
	} else if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Error("q did not return tea.Quit")
	}
}

func TestNarrowAndEmpty(t *testing.T) {
	m := model(t)
	for _, w := range []int{40, 70, 100, 200} {
		m.width, m.height = w, 12
		for _, l := range strings.Split(m.render(), "\n") {
			if ansi.StringWidth(l) > w {
				t.Errorf("width %d: line overflows: %q", w, ansi.Strip(l))
			}
		}
	}
	m.findings, m.width, m.height = nil, 100, 30
	if !strings.Contains(m.render(), "Nothing at medium") {
		t.Error("empty timeline should say so")
	}
}

func TestCopyBrief(t *testing.T) {
	m := model(t)
	if cmd := m.key("y"); cmd == nil {
		t.Fatal("y should copy a brief")
	}
	rs := m.rows()
	cur := m.current(rs)
	text := m.brief(cur)
	for _, want := range []string{"## Focus: the finding the user selected", m.cfg.Redactor.String(cur.Title), "## Findings, most severe first", "Foo crashed", "## What I need"} {
		if !strings.Contains(text, want) {
			t.Errorf("brief lacks %q:\n%s", want, text)
		}
	}
	// The filter narrows the brief to what is on screen.
	m.filter = "agent"
	if text := m.brief(nil); strings.Contains(text, "Foo crashed") || !strings.Contains(text, "com.foo.agent") {
		t.Errorf("filtered brief:\n%s", text)
	}
	m.filter = "nothing matches this"
	if text := m.brief(nil); !strings.Contains(text, "No shown row matches") {
		t.Errorf("a filter that hides everything should not fall back to every row:\n%s", text)
	}
	m.filter = ""
	press(m, "enter")
	if m.view != cardView || m.cardKey("y") == nil {
		t.Error("y in a card should copy a brief")
	}
	if !strings.Contains(m.render(), "y copy for AI") {
		t.Error("the card should name y")
	}
}

func TestOSC52Fallback(t *testing.T) {
	m := model(t)
	_, cmd := m.Update(osc52Msg{text: "hello", done: "copied"})
	if cmd == nil || !strings.Contains(m.status, "copied") {
		t.Errorf("osc52 fallback: cmd %v, status %q", cmd, m.status)
	}
}
