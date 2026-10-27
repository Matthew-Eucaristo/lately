package darwin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// LogPath is the real log binary. `log` alone is a zsh builtin, so every
// command lately prints spells out the path.
const LogPath = "/usr/bin/log"

// Record is the part of a `log show --style ndjson` line lately reads.
type Record struct {
	Timestamp        string `json:"timestamp"`
	MessageType      string `json:"messageType"`
	Subsystem        string `json:"subsystem"`
	Category         string `json:"category"`
	ProcessImagePath string `json:"processImagePath"`
	ProcessID        int    `json:"processID"`
	BootUUID         string `json:"bootUUID"`
	FormatString     string `json:"formatString"`
	EventMessage     string `json:"eventMessage"`
}

// Time parses the record's timestamp.
func (r Record) Time() (time.Time, error) {
	return time.Parse("2006-01-02 15:04:05.000000-0700", r.Timestamp)
}

// A parser turns records into events. Lenses get a fresh parser per run so
// they can correlate records (TCC spreads one decision over several lines).
type parser func(r Record, emit func(event.Event))

// Lens is one narrow unified-log query.
type Lens struct {
	Name      string
	Predicate string
	Approx    bool // message text is undocumented, so results are approximate
	newParser func() parser
}

// LogSource runs one lens through /usr/bin/log show.
type LogSource struct{ Lens Lens }

func (s *LogSource) ID() string        { return "log." + s.Lens.Name }
func (s *LogSource) Tier() source.Tier { return source.TierUser }

func (s *LogSource) Probe(context.Context) source.Capability {
	if _, err := os.Stat(LogPath); err != nil {
		return source.Capability{Needs: []string{"macos"}, Note: LogPath + " not found"}
	}
	return source.Capability{Available: true}
}

// Command is the exact command a user can paste to see the same records.
func (s *LogSource) Command(since, until time.Time) []string {
	return []string{LogPath, "show", "--style", "ndjson",
		"--start", since.Local().Format(localTime), "--end", until.Local().Format(localTime),
		"--predicate", s.Lens.Predicate}
}

func (s *LogSource) History(ctx context.Context, since, until time.Time, emit func(event.Event)) error {
	args := s.Command(since, until)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	perr := s.Parse(out, emit)
	if perr != nil {
		cancel() // stop log before Wait, or it blocks on a full pipe
	}
	werr := cmd.Wait()
	if perr != nil {
		return perr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if werr != nil {
		return fmt.Errorf("%s: %w", s.ID(), werr)
	}
	return nil
}

// StreamCommand is the live form of Command, for follow mode.
func (s *LogSource) StreamCommand() []string {
	return []string{LogPath, "stream", "--style", "ndjson", "--predicate", s.Lens.Predicate}
}

// Follow runs `log stream` with the lens predicate until ctx ends. It sees
// only records written from now on; History covers the past.
func (s *LogSource) Follow(ctx context.Context, emit func(event.Event)) error {
	args := s.StreamCommand()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	perr := s.parse(out, emit, true)
	stopped := ctx.Err() != nil
	cancel() // stop log before Wait, or it blocks on a full pipe
	werr := cmd.Wait()
	switch {
	case stopped:
		return nil
	case perr != nil:
		return perr
	case werr != nil:
		return fmt.Errorf("%s: log stream: %w", s.ID(), werr)
	}
	return fmt.Errorf("%s: log stream ended unexpectedly", s.ID())
}

// Parse reads ndjson records from r. Lines that are not records (the
// trailing {"count":…,"finished":1}) are skipped; a line that is not JSON
// at all is an error, because the format has changed.
func (s *LogSource) Parse(r io.Reader, emit func(event.Event)) error {
	return s.parse(r, emit, false)
}

// streamBanner is the one plain-text line `log stream` prints first.
const streamBanner = "Filtering the log data using "

func (s *LogSource) parse(r io.Reader, emit func(event.Event), stream bool) error {
	p := s.Lens.newParser()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 || stream && strings.HasPrefix(string(line), streamBanner) {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("%s: unreadable log record: %w", s.ID(), err)
		}
		if rec.Timestamp == "" {
			continue // the trailing summary line
		}
		if _, err := rec.Time(); err != nil {
			return fmt.Errorf("%s: unreadable timestamp %q", s.ID(), rec.Timestamp)
		}
		p(rec, func(e event.Event) {
			e.Source = s.ID()
			e.Approx = e.Approx || s.Lens.Approx
			e.Redactions += strings.Count(rec.EventMessage, "<private>")
			if e.Raw == "" {
				e.Raw = rec.EventMessage
			}
			if e.Subject.PID == 0 && e.Kind != event.KindLaunch {
				e.Subject.PID = rec.ProcessID
			}
			e.Set("predicate", s.Lens.Predicate)
			emit(e)
		})
	}
	return sc.Err()
}

// stateless wraps a simple per-record function as a lens parser factory.
func stateless(f func(r Record, emit func(event.Event))) func() parser {
	return func() parser { return f }
}

// newEvent starts an event from a record's timestamp.
func newEvent(r Record, kind string) (event.Event, bool) {
	t, err := r.Time()
	if err != nil {
		return event.Event{}, false
	}
	return event.Event{TS: t, Kind: kind}, true
}

// Lenses are the default unified-log queries. Each predicate filters on
// subsystem and message template so `log show` returns hundreds of records
// per day, not millions. Measured on an M4 with macOS 27.0.1 (all eight in
// parallel): 1.8 s for 15 minutes, 1.8 s for an hour, 38 s for a day, where
// RunningBoard is the long pole.
func Lenses() []*LogSource {
	ls := []Lens{
		{Name: "launch", Predicate: `subsystem == "com.apple.runningboard" AND formatString BEGINSWITH "Now tracking process"`, newParser: stateless(parseLaunch)},
		{Name: "tcc", Predicate: `subsystem == "com.apple.TCC" AND (formatString BEGINSWITH "AUTHREQ_CTX" OR formatString BEGINSWITH "AUTHREQ_ATTRIBUTION" OR formatString BEGINSWITH "AUTHREQ_RESULT")`, Approx: true, newParser: newTCCParser},
		{Name: "gatekeeper", Predicate: `subsystem == "com.apple.syspolicy.exec" AND formatString BEGINSWITH "GK evaluateScanResult"`, Approx: true, newParser: stateless(parseGatekeeper)},
		{Name: "xprotect", Predicate: `subsystem == "com.apple.XProtectFramework.PluginAPI" AND category == "XPEvent.structured"`, newParser: stateless(parseXProtect)},
		{Name: "btm", Predicate: `subsystem == "com.apple.backgroundtaskmanagement" AND (formatString BEGINSWITH "registerLaunchItem" OR formatString BEGINSWITH "registerItem" OR formatString BEGINSWITH "unregister")`, Approx: true, newParser: stateless(parseBTM)},
		{Name: "panic", Predicate: `subsystem == "com.apple.DumpPanic" OR (subsystem == "com.apple.osanalytics.preoslog" AND eventMessage CONTAINS[c] "panic")`, newParser: stateless(parsePanicLog)},
		{Name: "kernel", Predicate: `process == "kernel" AND (eventMessage CONTAINS "memorystatus: kill" OR eventMessage CONTAINS "shutdown cause")`, newParser: stateless(parseKernel)},
		{Name: "logerase", Predicate: `subsystem == "com.apple.log" AND eventMessage CONTAINS "erase"`, newParser: stateless(parseLogErase)},
	}
	out := make([]*LogSource, len(ls))
	for i := range ls {
		out[i] = &LogSource{Lens: ls[i]}
	}
	return out
}

// LensByName finds a default lens, for tests and fixtures.
func LensByName(name string) *LogSource {
	for _, l := range Lenses() {
		if l.Lens.Name == name {
			return l
		}
	}
	return nil
}
