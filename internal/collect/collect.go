// Package collect runs sources in parallel and streams their events, then
// diffs snapshots against the baseline for changes made since the last run.
package collect

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Options select the window and sources.
type Options struct {
	Since, Until time.Time
	Sources      []source.Source
	Baseline     *baseline.Baseline
}

// Update is one batch from one source. Done is set on the source's last
// batch; Final on the very last update of the run.
type Update struct {
	Source  string
	Events  []event.Event
	Err     error
	Done    bool
	Final   bool
	Elapsed time.Duration
	Notes   []string
}

// Stream runs every available source and sends updates until all are done.
// The channel is closed after the Final update.
func Stream(ctx context.Context, o Options) <-chan Update {
	ch := make(chan Update, 64)
	send := func(u Update) {
		select {
		case ch <- u:
		case <-ctx.Done(): // nobody is listening any more
		}
	}
	go func() {
		defer close(ch)
		var wg sync.WaitGroup
		var mu sync.Mutex
		seen := map[string]bool{} // persistence files already reported by History
		for _, s := range o.Sources {
			if cp := s.Probe(ctx); !cp.Available {
				send(Update{Source: s.ID(), Done: true, Err: fmt.Errorf("unavailable: %s", cp.Note)})
				continue
			}
			wg.Add(1)
			go func(s source.Source) {
				defer wg.Done()
				start := time.Now()
				var batch []event.Event
				flush := func(done bool, err error) {
					send(Update{Source: s.ID(), Events: batch, Done: done, Err: err, Elapsed: time.Since(start)})
					batch = nil
				}
				err := s.History(ctx, o.Since, o.Until, func(e event.Event) {
					if e.Kind == event.KindPersist {
						mu.Lock()
						seen[persistKey(e)] = true
						mu.Unlock()
					}
					batch = append(batch, e)
					if len(batch) >= 200 {
						flush(false, nil)
					}
				})
				flush(true, err)
			}(s)
		}
		wg.Wait()
		final := Update{Source: "snapshot", Done: true, Final: true}
		if o.Baseline != nil && ctx.Err() == nil {
			final.Events, final.Notes = snapshotEvents(ctx, o, seen)
		}
		send(final)
	}()
	return ch
}

func persistKey(e event.Event) string {
	if p := e.Field("plist"); p != "" {
		return p
	}
	return e.Field("file")
}

// snapshotEvents turns baseline differences into events. Their exact time
// is unknown, so they are dated now and marked approximate.
func snapshotEvents(ctx context.Context, o Options, seen map[string]bool) ([]event.Event, []string) {
	var items []source.Item
	var failed []string
	for _, s := range o.Sources {
		if sn, ok := s.(source.Snapshotter); ok {
			got, bad := sn.Snapshot(ctx)
			items = append(items, got...)
			failed = append(failed, bad...)
		}
	}
	if ctx.Err() != nil {
		return nil, nil // cancelled mid-snapshot: a partial snapshot must not be saved
	}
	last := o.Baseline.LastRun()
	added, changed, removed := o.Baseline.Diff(items, failed)
	now := time.Now()
	var out []event.Event
	add := func(it source.Item, change string) {
		e := event.Event{TS: now, Source: "snapshot", Kind: it.Kind, Subject: it.Subject, Approx: true}
		for k, v := range it.Fields {
			e.Set(k, v)
		}
		if seen[persistKey(e)] {
			return
		}
		e.Set("change", change)
		if !last.IsZero() {
			e.Set("since", "since lately last ran ("+last.Local().Format("Jan 2 15:04")+")")
		}
		out = append(out, e)
	}
	for _, it := range added {
		add(it, "added")
	}
	for _, it := range changed {
		add(it, "changed")
	}
	var notes []string
	if len(failed) > 0 {
		notes = append(notes, "could not read "+strings.Join(failed, ", ")+"; their changes since the last run are not shown")
	}
	if removed > 0 {
		notes = append(notes, fmt.Sprintf("%d watched item(s) disappeared since the last run (the baseline stores no names)", removed))
	}
	return out, notes
}

// Result is a whole collection run.
type Result struct {
	Events  []event.Event
	Errors  map[string]error
	Elapsed map[string]time.Duration
	Notes   []string
}

// Collect drains Stream.
func Collect(ctx context.Context, o Options) *Result {
	r := &Result{Errors: map[string]error{}, Elapsed: map[string]time.Duration{}}
	for u := range Stream(ctx, o) {
		r.Add(u)
	}
	return r
}

// Add folds one update into the result.
func (r *Result) Add(u Update) {
	r.Events = append(r.Events, u.Events...)
	r.Notes = append(r.Notes, u.Notes...)
	if u.Err != nil {
		r.Errors[u.Source] = u.Err
	}
	if u.Done {
		r.Elapsed[u.Source] = u.Elapsed
	}
}

// Redactions totals the <private> fields macOS hid in log records.
func (r *Result) Redactions() int {
	n := 0
	for _, e := range r.Events {
		n += e.Redactions
	}
	return n
}

// shells and terminals whose brief appearance is the "flashing window".
var flashTargets = map[string]bool{
	"zsh": true, "bash": true, "sh": true, "fish": true, "dash": true, "tcsh": true, "csh": true,
	"Terminal": true, "iTerm2": true, "login": true,
}

// non-interactive parents: a shell started by these was not typed by a person.
var flashParents = map[string]bool{"osascript": true, "launchd": true, "cron": true, "atrun": true, "AppleScript": true}

// Flash turns an exit of a short-lived shell or terminal started by a
// non-interactive parent into an "exec.flash" event.
func Flash(t *ancestry.Tree, exit event.Event) (event.Event, bool) {
	n, ok := t.Get(exit.Subject.PID)
	if !ok {
		return event.Event{}, false
	}
	lived, ok := n.Lived()
	if !ok || lived > 2*time.Second || !flashTargets[n.Name()] {
		return event.Event{}, false
	}
	c := t.Chain(n.PID)
	if len(c.Nodes) < 2 {
		return event.Event{}, false // parent unknown: no guessing
	}
	p := c.Nodes[len(c.Nodes)-2]
	parent := p.Name()
	if p.PID == 1 {
		parent = "launchd"
	}
	trigger := flashParents[parent]
	for k := len(c.Nodes) - 2; k >= 0 && k >= len(c.Nodes)-4; k-- {
		if c.Nodes[k].Name() == "osascript" {
			trigger = true
		}
	}
	if !trigger {
		return event.Event{}, false
	}
	e := event.Event{TS: n.Start, Source: "eslogger", Kind: event.KindExec,
		Subject: event.Subject{Name: n.Name(), Path: n.Path, PID: n.PID, PPID: n.PPID, Signer: n.Signer, TeamID: n.TeamID}}
	e.Set("op", "flash")
	e.Set("parent_name", parent)
	e.Set("args", n.Args)
	e.Set("lived", fmt.Sprintf("%.2fs", lived.Seconds()))
	e.Set("chain", chainText(c))
	return e, true
}

func chainText(c ancestry.Chain) string {
	var parts []string
	for _, n := range c.Nodes {
		parts = append(parts, fmt.Sprintf("%s(%d)", n.Name(), n.PID))
	}
	if c.Broken {
		parts = append([]string{fmt.Sprintf("…(%d unknown)", c.Gap)}, parts...)
	}
	return strings.Join(parts, " → ")
}
