package ui

import (
	"os"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/darwin"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/report"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// drive runs cmd and feeds every resulting message back until the model
// stops loading.
func drive(m *Model, cmd tea.Cmd) {
	q := make(chan tea.Msg, 1024)
	var run func(tea.Cmd)
	run = func(c tea.Cmd) {
		if c == nil {
			return
		}
		go func() { q <- c() }()
	}
	run(cmd)
	for m.loading {
		msg := <-q
		if b, ok := msg.(tea.BatchMsg); ok {
			for _, c := range b {
				run(c)
			}
			continue
		}
		_, c := m.Update(msg)
		run(c)
	}
}

func TestRealTiming(t *testing.T) {
	if os.Getenv("LATELY_REAL") == "" {
		t.Skip("set LATELY_REAL=1")
	}
	home, _ := os.UserHomeDir()
	now := time.Now()
	m := New(Config{Meta: report.Meta{Since: now.Add(-15 * time.Minute), Until: now, Window: "15m", Floor: event.Medium},
		Rules: rules.Builtin(), Baseline: baseline.Disable(),
		SourcesFor: func(w time.Duration) []source.Source { return darwin.Sources(home, w) }})
	st := time.Now()
	drive(m, m.Init())
	t.Logf("15m load %.1fs, %d events", time.Since(st).Seconds(), len(m.all))
	for _, k := range []string{"t", "t", "t", "t", "t", "T", "T", "T"} {
		st := time.Now()
		drive(m, m.key(k))
		t.Logf("%s → %-4s %.1fs, %d events, %d findings", k, m.meta.Window, time.Since(st).Seconds(), len(m.all), len(m.findings))
	}
}
