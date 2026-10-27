package darwin

import (
	"bufio"
	"context"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Power reads `pmset -g log` (sleep, wake, dark wake, failures). pmset has
// no time filter and takes about 4 s on a busy Mac, so it runs alongside the
// log lenses rather than before the first frame.
type Power struct{}

func (Power) ID() string        { return "pmset" }
func (Power) Tier() source.Tier { return source.TierUser }
func (Power) Probe(context.Context) source.Capability {
	return source.Capability{Available: true}
}

func (p Power) History(ctx context.Context, since, until time.Time, emit func(event.Event)) error {
	log, err := PowerLog(ctx)
	if err != nil {
		return err
	}
	for _, l := range log.Lines {
		if inWindow(l.TS, since, until) && powerKinds[l.Type] {
			emit(l.event())
		}
	}
	return nil
}

// powerKinds are the pmset line types shown on the timeline.
var powerKinds = map[string]bool{
	"Sleep": true, "Wake": true, "DarkWake": true, "Start": true, "Failure": true,
	"Shutdown": true, "Restart": true, "ShutdownCause": true,
}

// PowerLine is one dated pmset log line.
type PowerLine struct {
	TS      time.Time
	Type    string
	Details string
}

func (l PowerLine) event() event.Event {
	e := event.Event{TS: l.TS, Source: "pmset", Kind: event.KindPower, Raw: l.Type + " " + l.Details}
	e.Subject = event.Subject{Name: "powerd", Signer: event.SignerApple}
	e.Set("type", l.Type)
	e.Set("details", l.Details)
	if m := powerReason.FindStringSubmatch(l.Details); m != nil {
		e.Set("reason", strings.TrimSpace(m[1]))
	}
	return e
}

// PowerLogData is the parsed log, sorted by time.
type PowerLogData struct{ Lines []PowerLine }

var (
	pmsetLine   = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}) (\S+)\s+(.*)$`)
	powerReason = regexp.MustCompile(`due to ([^:\n]+?)(?:\s+Using|:|$)`)
	powerSource = regexp.MustCompile(`Using (AC|Batt|BATT)(?:\s*\(Charge:\s*(\d+)%?\))?`)
)

// PowerLog runs pmset and parses its output.
func PowerLog(ctx context.Context) (*PowerLogData, error) {
	out, err := runCmd(ctx, "/usr/bin/pmset", "-g", "log")
	if err != nil {
		return nil, err
	}
	return ParsePowerLog(strings.NewReader(string(out)))
}

// ParsePowerLog reads pmset -g log text. Lines without a leading date are
// headers or wrapped details and are skipped.
func ParsePowerLog(r io.Reader) (*PowerLogData, error) {
	d := &PowerLogData{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		m := pmsetLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		t, err := time.Parse("2006-01-02 15:04:05 -0700", m[1])
		if err != nil {
			continue
		}
		d.Lines = append(d.Lines, PowerLine{TS: t, Type: m[2], Details: strings.TrimSpace(m[3])})
	}
	sort.SliceStable(d.Lines, func(i, j int) bool { return d.Lines[i].TS.Before(d.Lines[j].TS) })
	return d, sc.Err()
}

// Before returns the last line strictly before t, if any.
func (d *PowerLogData) Before(t time.Time) (PowerLine, bool) {
	i := sort.Search(len(d.Lines), func(i int) bool { return !d.Lines[i].TS.Before(t) })
	if i == 0 {
		return PowerLine{}, false
	}
	return d.Lines[i-1], true
}

// SourceBefore reports the last known power source before t ("AC" or
// "Battery") and the charge, from the assertion summaries pmset logs.
func (d *PowerLogData) SourceBefore(t time.Time) (src, charge string) {
	i := sort.Search(len(d.Lines), func(i int) bool { return !d.Lines[i].TS.Before(t) })
	for j := i - 1; j >= 0 && j >= i-5000; j-- {
		if m := powerSource.FindStringSubmatch(d.Lines[j].Details); m != nil {
			src = "AC"
			if m[1] != "AC" {
				src = "Battery"
			}
			return src, m[2]
		}
	}
	return "", ""
}
