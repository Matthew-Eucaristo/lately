package darwin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Reports reads crash, hang, jetsam and shutdown-stall reports from both
// DiagnosticReports folders (and their Retired subfolders). For .ips files
// the first line is a JSON header, so triage reads one line per file.
type Reports struct {
	Dirs  []string
	Every time.Duration // follow poll interval; FollowPoll when zero
}

// NewReports uses the user and system report folders.
func NewReports(home string) *Reports {
	return &Reports{Dirs: []string{
		filepath.Join(home, "Library/Logs/DiagnosticReports"),
		"/Library/Logs/DiagnosticReports",
	}}
}

func (s *Reports) ID() string        { return "reports" }
func (s *Reports) Tier() source.Tier { return source.TierUser }

func (s *Reports) Probe(context.Context) source.Capability {
	for _, d := range s.Dirs {
		if _, err := os.ReadDir(d); err == nil {
			return source.Capability{Available: true}
		}
	}
	return source.Capability{Note: "no readable DiagnosticReports folder"}
}

func (s *Reports) History(ctx context.Context, since, until time.Time, emit func(event.Event)) error {
	return s.scan(ctx, since, func(path string, fi fs.FileInfo) {
		if e, ok := ReadReport(path, fi.ModTime()); ok && inWindow(e.TS, since, until) {
			emit(e)
		}
	})
}

// Follow emits every report file that appears from now on, whatever its
// incident time: ReportCrash can write a hang or spin report long after
// the incident, so a time window would miss it.
func (s *Reports) Follow(ctx context.Context, emit func(event.Event)) error {
	every := s.Every
	if every <= 0 {
		every = FollowPoll
	}
	done := map[string]bool{}
	from := time.Now()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		err := s.scan(ctx, from.Add(-every), func(path string, fi fs.FileInfo) {
			if done[path] {
				return
			}
			done[path] = true
			if e, ok := ReadReport(path, fi.ModTime()); ok {
				emit(e)
			}
		})
		if err != nil && ctx.Err() == nil {
			return err
		}
	}
}

// scan calls f for each report file modified at or after since.
func (s *Reports) scan(ctx context.Context, since time.Time, f func(string, fs.FileInfo)) error {
	var errs []error
	for _, d := range s.Dirs {
		for _, dir := range []string{d, filepath.Join(d, "Retired")} {
			ents, err := os.ReadDir(dir)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					errs = append(errs, err)
				}
				continue
			}
			for _, ent := range ents {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if ent.IsDir() {
					continue
				}
				fi, err := ent.Info()
				if err != nil || fi.ModTime().Before(since) {
					continue // a report is written after its incident
				}
				f(filepath.Join(dir, ent.Name()), fi)
			}
		}
	}
	return errors.Join(errs...)
}

// IPSHeader is the first line of an .ips file.
type IPSHeader struct {
	BugType      string `json:"bug_type"`
	AppName      string `json:"app_name"`
	Name         string `json:"name"`
	BundleID     string `json:"bundleID"`
	AppVersion   string `json:"app_version"`
	Timestamp    string `json:"timestamp"`
	IncidentID   string `json:"incident_id"`
	IsSimulated  int    `json:"is_simulated"`
	IsFirstParty int    `json:"is_first_party"`
}

// ipsBody is the part of a crash report body lately shows on a card.
type ipsBody struct {
	ProcPath        string `json:"procPath"`
	ParentProc      string `json:"parentProc"`
	ResponsibleProc string `json:"responsibleProc"`
	TeamID          string `json:"codeSigningTeamID"`
	Exception       struct {
		Type   string `json:"type"`
		Signal string `json:"signal"`
	} `json:"exception"`
	Termination struct {
		Indicator string `json:"indicator"`
		Namespace string `json:"namespace"`
	} `json:"termination"`
}

var reportStamp = regexp.MustCompile(`^(.*?)[-_](\d{4}-\d{2}-\d{2}-\d{6})(?:[_.]|$)`)

// ReadReport classifies one report file. fallback is used when neither the
// header nor the file name carries a time.
func ReadReport(path string, fallback time.Time) (event.Event, bool) {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		return event.Event{}, false
	}
	e := event.Event{TS: fallback, Source: "reports", Kind: event.KindCrash}
	e.Set("file", ReportName(base))
	e.Set("report_path", path)
	name, stamp := base, ""
	if m := reportStamp.FindStringSubmatch(base); m != nil {
		name, stamp = m[1], m[2]
		if t, err := time.ParseInLocation("2006-01-02-150405", stamp, time.Local); err == nil {
			e.TS = t
		}
	}
	e.Subject.Name = strings.TrimPrefix(name, "ExcUserFault_")
	ext := filepath.Ext(base)
	if ext == ".ips" {
		f, err := os.Open(path)
		if err != nil {
			e.Set("report_kind", "unreadable")
			return e, true
		}
		defer f.Close()
		if !readIPS(f, &e) {
			e.Set("report_kind", "unknown")
		}
		return e, true
	}
	e.Set("report_kind", kindFromName(name, ext))
	if e.Field("report_kind") == "jetsam" {
		e.Subject.Name = "processes"
	}
	return e, true
}

// readIPS fills e from an .ips stream: header line, then (for crashes) the
// body JSON.
func readIPS(r io.Reader, e *event.Event) bool {
	br := bufio.NewReaderSize(r, 64*1024)
	line, err := br.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return false
	}
	var h IPSHeader
	if json.Unmarshal(line, &h) != nil {
		return false
	}
	if t, err := time.Parse("2006-01-02 15:04:05.00 -0700", h.Timestamp); err == nil {
		e.TS = t
	}
	if h.AppName != "" {
		e.Subject.Name = h.AppName
	} else if h.Name != "" {
		e.Subject.Name = h.Name
	}
	e.Subject.BundleID = h.BundleID
	e.Set("bug_type", h.BugType)
	e.Set("version", h.AppVersion)
	kind := kindFromBugType(h.BugType)
	if h.IsSimulated == 1 && kind == "crash" {
		kind = "fault" // a simulated crash report: the process kept running
	}
	if kind == "unknown" {
		kind = kindFromName(e.Field("file"), ".ips")
	}
	e.Set("report_kind", kind)
	if kind == "jetsam" {
		e.Subject.Name = "processes"
	}
	if h.IsFirstParty == 1 {
		e.Set("first_party", "yes")
	}
	if kind != "crash" {
		return true
	}
	var b ipsBody
	if json.NewDecoder(br).Decode(&b) == nil {
		e.Subject.Path = b.ProcPath
		e.Subject.TeamID = b.TeamID
		e.Subject.Responsible = b.ResponsibleProc
		e.Set("parent", b.ParentProc)
		e.Set("exception", strings.TrimSpace(b.Exception.Type+" "+b.Exception.Signal))
		e.Set("termination", b.Termination.Indicator)
	}
	return true
}

// Bug types seen in the header. Apple does not document this table; these
// codes were checked against reports on macOS 27 (309, 298) and the rest are
// widely reported. Anything else falls back to the file name.
func kindFromBugType(t string) string {
	switch t {
	case "309", "109":
		return "crash"
	case "210":
		return "panic"
	case "298":
		return "jetsam"
	case "228", "385":
		return "hang"
	case "202", "284", "285", "145", "211":
		return "resource"
	}
	return "unknown"
}

func kindFromName(name, ext string) string {
	switch {
	case strings.HasPrefix(name, "JetsamEvent"):
		return "jetsam"
	case strings.HasPrefix(name, "shutdown_stall") || ext == ".shutdownStall":
		return "stall"
	case ext == ".panic" || strings.HasPrefix(name, "panic") || strings.HasPrefix(name, "Kernel"):
		return "panic"
	case strings.HasPrefix(name, "ExcUserFault"):
		return "fault"
	case ext == ".hang" || ext == ".spin":
		return "hang"
	case ext == ".diag" || strings.HasSuffix(name, "_resource"):
		return "resource"
	case ext == ".crash":
		return "crash"
	}
	return "unknown"
}

// ReportName drops the host name macOS appends to report file names.
func ReportName(base string) string {
	if m := reportStamp.FindStringSubmatchIndex(base); m != nil {
		return base[:m[5]] + filepath.Ext(base)
	}
	return base
}
