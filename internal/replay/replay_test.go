package replay

import (
	"context"
	"testing"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

func TestLoadSample(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	d, err := Load("../../demo/sample", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Events) < 10 || d.Restart == nil || len(d.Capture) == 0 {
		t.Fatalf("sample incomplete: %d events, restart %v, capture %d bytes", len(d.Events), d.Restart != nil, len(d.Capture))
	}
	var got []event.Event
	_ = (&Source{Data: d}).History(context.Background(), now.Add(-15*time.Minute), now, func(e event.Event) { got = append(got, e) })
	if len(got) != len(d.Events) {
		t.Errorf("all sample events should land in the last 15 minutes, got %d of %d", len(got), len(d.Events))
	}
	if d.Restart.Boot.After(now) || !d.Restart.Boot.Before(now.Add(-time.Hour)) {
		t.Errorf("restart evidence not shifted with the events: %v", d.Restart.Boot)
	}
	if newestCapture(d.Capture).After(now) {
		t.Error("capture shifted past now")
	}
	if _, err := Load(t.TempDir(), now); err == nil {
		t.Error("a folder without events.ndjson must be an error")
	}
}

func TestLivePlaysAfterFollowStarts(t *testing.T) {
	d, err := Load("../../demo/sample", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Live) == 0 {
		t.Fatal("the sample should have live events")
	}
	for i, l := range d.Live {
		if l.After <= 0 || l.After > time.Minute || i > 0 && l.After < d.Live[i-1].After {
			t.Errorf("live event %d arrives after %v", i, l.After)
		}
	}
	// Play the first event only, compressed in time.
	d.Live = []Live{{After: 10 * time.Millisecond, Event: d.Live[0].Event}}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	var got []event.Event
	_ = (&Source{Data: d}).Follow(ctx, func(e event.Event) { got = append(got, e); cancel() })
	if len(got) != 1 || got[0].TS.Before(start) {
		t.Errorf("live event not stamped with its arrival: %+v", got)
	}
}

func TestLiveResumesWhereItPaused(t *testing.T) {
	d, err := Load("../../demo/sample", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	d.Live = []Live{{After: 0, Event: d.Live[0].Event}, {After: 10 * time.Millisecond, Event: d.Live[1].Event}}
	s := &Source{Data: d}
	play := func() []event.Event {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		var got []event.Event
		_ = s.Follow(ctx, func(e event.Event) { got = append(got, e); cancel() })
		return got
	}
	a, b, c := play(), play(), play()
	if len(a) != 1 || len(b) != 1 || len(c) != 0 || a[0].Kind == b[0].Kind && a[0].Subject == b[0].Subject {
		t.Errorf("pause and resume replayed events: %d %d %d", len(a), len(b), len(c))
	}
}
