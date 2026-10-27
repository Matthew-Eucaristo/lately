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
