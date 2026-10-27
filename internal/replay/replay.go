// Package replay reads a folder of saved, normalized events instead of the
// live system. The demo and the sample data use it, so a recording never
// shows a real Mac's logs. Times are shifted so the newest event lands just
// before "now", which keeps the 15-minute view meaningful.
//
// A replay folder holds:
//
//	events.ndjson    one event.Event per line (required)
//	capture.ndjson   eslogger JSON lines for the ancestry view (optional)
//	restart.json     restart.Evidence for the restart view (optional)
package replay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/restart"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Data is a loaded replay folder.
type Data struct {
	Events  []event.Event
	Capture []byte // raw eslogger lines, already time-shifted
	Restart *restart.Evidence
	Shift   time.Duration
}

// Load reads dir and shifts every time by the same amount.
func Load(dir string, now time.Time) (*Data, error) {
	f, err := os.Open(filepath.Join(dir, "events.ndjson"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	d := &Data{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e event.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("%s line %d: %w", f.Name(), n, err)
		}
		d.Events = append(d.Events, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	var newest time.Time
	for _, e := range d.Events {
		if e.TS.After(newest) {
			newest = e.TS
		}
	}
	capture, err := os.ReadFile(filepath.Join(dir, "capture.ndjson"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if t := newestCapture(capture); t.After(newest) {
		newest = t
	}
	if !newest.IsZero() {
		d.Shift = now.Add(-30 * time.Second).Sub(newest).Truncate(time.Second)
	}
	for i := range d.Events {
		d.Events[i].TS = d.Events[i].TS.Add(d.Shift)
		d.Events[i].Source = "replay:" + d.Events[i].Source
	}
	if b, err := os.ReadFile(filepath.Join(dir, "restart.json")); err == nil {
		var ev restart.Evidence
		if err := json.Unmarshal(b, &ev); err != nil {
			return nil, fmt.Errorf("restart.json: %w", err)
		}
		ev.Boot = ev.Boot.Add(d.Shift)
		ev.PrevBoot = ev.PrevBoot.Add(d.Shift)
		ev.LastPowerTS = ev.LastPowerTS.Add(d.Shift)
		ev.LastWordsTS = ev.LastWordsTS.Add(d.Shift)
		if ev.ShutdownBefore != nil {
			t := ev.ShutdownBefore.Add(d.Shift)
			ev.ShutdownBefore = &t
		}
		d.Restart = &ev
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(capture) > 0 {
		if d.Capture, err = shiftCapture(capture, d.Shift); err != nil {
			return nil, fmt.Errorf("capture.ndjson: %w", err)
		}
	}
	return d, nil
}

// newestCapture is the latest "time" in eslogger lines.
func newestCapture(b []byte) time.Time {
	var newest time.Time
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var l struct {
			Time time.Time `json:"time"`
		}
		if json.Unmarshal(sc.Bytes(), &l) == nil && l.Time.After(newest) {
			newest = l.Time
		}
	}
	return newest
}

// shiftCapture moves the "time" field of each eslogger line.
func shiftCapture(b []byte, shift time.Duration) ([]byte, error) {
	var out []byte
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			return nil, err
		}
		if s, ok := m["time"].(string); ok {
			if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
				m["time"] = t.Add(shift).Format(time.RFC3339Nano)
			}
		}
		line, _ := json.Marshal(m)
		out = append(append(out, line...), '\n')
	}
	return out, sc.Err()
}

// Source serves the loaded events as one source.
type Source struct{ Data *Data }

func (s *Source) ID() string        { return "replay" }
func (s *Source) Tier() source.Tier { return source.TierUser }
func (s *Source) Probe(context.Context) source.Capability {
	return source.Capability{Available: true, Note: "replayed sample data"}
}

func (s *Source) History(_ context.Context, since, until time.Time, emit func(event.Event)) error {
	for _, e := range s.Data.Events {
		if !e.TS.Before(since) && !e.TS.After(until) {
			emit(e)
		}
	}
	return nil
}
