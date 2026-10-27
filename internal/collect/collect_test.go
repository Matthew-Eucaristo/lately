package collect

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

func proc(ts time.Time, kind string, pid, ppid int, path, args string) event.Event {
	e := event.Event{TS: ts, Kind: kind, Subject: event.Subject{PID: pid, PPID: ppid, Path: path}}
	if args != "" {
		e.Set("args", args)
	}
	return e
}

func TestFlash(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 15, 0, 31, 0, time.UTC)
	tr := ancestry.New("capture")
	tr.Add(proc(t0, event.KindExec, 100, 1, "/usr/bin/osascript", "osascript -e …"))
	tr.Add(proc(t0.Add(10*time.Millisecond), event.KindExec, 101, 100, "/bin/zsh", "zsh -c curl … | sh"))
	exit := proc(t0.Add(400*time.Millisecond), event.KindExit, 101, 0, "", "")
	tr.Add(exit)
	f, ok := Flash(tr, exit)
	if !ok || f.Field("parent_name") != "osascript" || f.Field("op") != "flash" {
		t.Fatalf("flash not detected: %+v", f)
	}
	// An interactive shell's child is not a flash.
	tr.Add(proc(t0, event.KindExec, 200, 1, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ""))
	tr.Add(proc(t0, event.KindExec, 201, 200, "/bin/zsh", "-zsh"))
	tr.Add(proc(t0, event.KindExec, 202, 201, "/bin/sh", "sh -c ls"))
	e2 := proc(t0.Add(time.Second), event.KindExit, 202, 0, "", "")
	tr.Add(e2)
	if _, ok := Flash(tr, e2); ok {
		t.Error("a typed command flagged as flash")
	}
}

type fakeSource struct {
	id     string
	evs    []event.Event
	items  []source.Item
	failed []string
}

func (f *fakeSource) ID() string        { return f.id }
func (f *fakeSource) Tier() source.Tier { return source.TierUser }
func (f *fakeSource) Probe(context.Context) source.Capability {
	return source.Capability{Available: true}
}
func (f *fakeSource) Snapshot(context.Context) ([]source.Item, []string) { return f.items, f.failed }
func (f *fakeSource) History(_ context.Context, _, _ time.Time, emit func(event.Event)) error {
	for _, e := range f.evs {
		emit(e)
	}
	return nil
}

func TestCollectDiffsSnapshots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	b := baseline.Open(path)
	src := &fakeSource{id: "fake", items: []source.Item{{Group: "cron", Key: "cron:a", Hash: "1", Kind: event.KindPersist, Fields: map[string]string{"persist": "cron"}}}}
	o := Options{Since: time.Now().Add(-time.Hour), Until: time.Now(), Sources: []source.Source{src}, Baseline: b}
	if r := Collect(context.Background(), o); len(r.Events) != 0 {
		t.Fatalf("first run must only build the baseline, got %d events", len(r.Events))
	}
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	src.items = append(src.items, source.Item{Group: "cron", Key: "cron:b", Hash: "2", Kind: event.KindPersist, Fields: map[string]string{"persist": "cron"}})
	src.items[0].Hash = "changed"
	o.Baseline = baseline.Open(path)
	r := Collect(context.Background(), o)
	changes := map[string]int{}
	for _, e := range r.Events {
		changes[e.Field("change")]++
		if !e.Approx {
			t.Error("snapshot events have no exact time and must be approximate")
		}
	}
	if changes["added"] != 1 || changes["changed"] != 1 {
		t.Errorf("changes %v", changes)
	}
}

func TestFailedGroupIsNotReportedAsAdded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	ext := source.Item{Group: "sysext", Key: "sysext:com.example.filter", Hash: "1", Kind: event.KindSysext}
	src := &fakeSource{id: "fake", items: []source.Item{ext}}
	o := Options{Since: time.Now().Add(-time.Hour), Until: time.Now(), Sources: []source.Source{src}, Baseline: baseline.Open(path)}
	Collect(context.Background(), o)
	if err := o.Baseline.Save(); err != nil {
		t.Fatal(err)
	}
	// systemextensionsctl fails once: nothing may be reported, nothing forgotten.
	src.items, src.failed = nil, []string{"sysext"}
	o.Baseline = baseline.Open(path)
	if r := Collect(context.Background(), o); len(r.Events) != 0 {
		t.Fatalf("a failed group produced events: %+v", r.Events)
	}
	if err := o.Baseline.Save(); err != nil {
		t.Fatal(err)
	}
	// It works again: the extension is still known, not "added".
	src.items, src.failed = []source.Item{ext}, nil
	o.Baseline = baseline.Open(path)
	if r := Collect(context.Background(), o); len(r.Events) != 0 {
		t.Fatalf("known extension reported again after a failed run: %+v", r.Events)
	}
}
