package darwin

import (
	"bufio"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Installs reads what got installed: InstallHistory.plist (packages, App
// Store, macOS updates), install.log (package requests the history may
// miss) and Homebrew's per-formula log folders.
type Installs struct {
	HistoryPlist string
	InstallLog   string
	HomebrewLog  string
}

// NewInstalls uses the standard locations; HOMEBREW_LOGS overrides
// Homebrew's.
func NewInstalls(home string) *Installs {
	brew := os.Getenv("HOMEBREW_LOGS")
	if brew == "" {
		brew = filepath.Join(home, "Library/Logs/Homebrew")
	}
	return &Installs{
		HistoryPlist: "/Library/Receipts/InstallHistory.plist",
		InstallLog:   "/var/log/install.log",
		HomebrewLog:  brew,
	}
}

func (s *Installs) ID() string        { return "installs" }
func (s *Installs) Tier() source.Tier { return source.TierUser }
func (s *Installs) Probe(context.Context) source.Capability {
	if _, err := os.Stat(s.HistoryPlist); err != nil {
		return source.Capability{Available: true, Note: "InstallHistory.plist not readable"}
	}
	return source.Capability{Available: true}
}

func (s *Installs) History(ctx context.Context, since, until time.Time, emit func(event.Event)) error {
	var errs []error
	seen := map[string]time.Time{}
	if f, err := os.Open(s.HistoryPlist); err == nil {
		err := ParseInstallHistory(f, func(e event.Event) {
			if inWindow(e.TS, since, until) {
				for _, p := range strings.Split(e.Field("packages"), ",") {
					seen[p] = e.TS
				}
				emit(e)
			}
		})
		f.Close()
		if err != nil {
			errs = append(errs, err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		errs = append(errs, err)
	}
	if f, err := os.Open(s.InstallLog); err == nil {
		err := ParseInstallLog(tailFrom(f, since), func(e event.Event) {
			if t, ok := seen[e.Subject.BundleID]; ok && absDur(t.Sub(e.TS)) < 30*time.Minute {
				return // InstallHistory already has it, with a nicer name
			}
			if inWindow(e.TS, since, until) {
				emit(e)
			}
		})
		f.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, homebrewInstalls(s.HomebrewLog, since, until, emit))
	return errors.Join(errs...)
}

type historyEntry struct {
	Date        time.Time `plist:"date"`
	DisplayName string    `plist:"displayName"`
	Version     string    `plist:"displayVersion"`
	Packages    []string  `plist:"packageIdentifiers"`
	Process     string    `plist:"processName"`
}

// ParseInstallHistory decodes InstallHistory.plist (plutil -convert json
// cannot, because of its dates).
func ParseInstallHistory(r io.ReadSeeker, emit func(event.Event)) error {
	var entries []historyEntry
	if err := plist.NewDecoder(r).Decode(&entries); err != nil {
		return err
	}
	for _, h := range entries {
		e := event.Event{TS: h.Date, Source: "installs", Kind: event.KindInstall}
		e.Subject = event.Subject{Name: h.DisplayName}
		if len(h.Packages) > 0 {
			e.Subject.BundleID = h.Packages[0]
		}
		e.Set("version", h.Version)
		e.Set("by", h.Process)
		e.Set("packages", strings.Join(h.Packages, ","))
		e.Set("via", "InstallHistory.plist")
		if strings.HasPrefix(e.Subject.BundleID, "com.apple.") || h.Process == "softwareupdated" {
			e.Subject.Signer = event.SignerApple
		}
		emit(e)
	}
	return nil
}

var (
	installReq = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{2}) \S+ (\w+)\[\d+\]: PackageKit: request=PKInstallRequest`)
	installPkg = regexp.MustCompile(`PKLeopardPackage <id=([^,]+), version=([^,]+)`)
)

// ParseInstallLog reads install.log package requests: a dated request line
// followed by undated PKLeopardPackage lines naming the packages.
func ParseInstallLog(r io.Reader, emit func(event.Event)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var at time.Time
	var by string
	for sc.Scan() {
		line := sc.Text()
		if m := installReq.FindStringSubmatch(line); m != nil {
			t, err := time.Parse("2006-01-02 15:04:05-07", m[1])
			if err == nil {
				at, by = t, m[2]
			}
			continue
		}
		if at.IsZero() {
			continue
		}
		if m := installPkg.FindStringSubmatch(line); m != nil {
			e := event.Event{TS: at, Source: "installs", Kind: event.KindInstall}
			e.Subject = event.Subject{Name: m[1], BundleID: m[1]}
			if strings.HasPrefix(m[1], "com.apple.") {
				e.Subject.Signer = event.SignerApple
			}
			e.Set("version", m[2])
			e.Set("by", by)
			e.Set("packages", m[1])
			e.Set("via", "install.log")
			emit(e)
		} else if len(line) > 4 && line[0] >= '0' && line[0] <= '9' && !strings.Contains(line, "PackageKit: packages=(") {
			at = time.Time{} // any other dated line ends the package list
		}
	}
	return sc.Err()
}

// tailFrom skips most of a large dated log: it seeks back in growing steps
// until the first dated line is older than since, then reads from there.
func tailFrom(f *os.File, since time.Time) io.Reader {
	fi, err := f.Stat()
	if err != nil {
		return f
	}
	size := fi.Size()
	for step := int64(1 << 20); step < size; step *= 4 {
		off := size - step
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			break
		}
		br := bufio.NewReader(f)
		_, _ = br.ReadString('\n') // partial line
		for i := 0; i < 200; i++ {
			line, err := br.ReadString('\n')
			if err != nil {
				break
			}
			if len(line) < 22 {
				continue
			}
			if t, err := time.Parse("2006-01-02 15:04:05-07", line[:22]); err == nil {
				if t.Before(since) {
					_, _ = f.Seek(off, io.SeekStart)
					return f
				}
				break
			}
		}
	}
	_, _ = f.Seek(0, io.SeekStart)
	return f
}

// homebrewInstalls treats each per-formula log folder's newest write as an
// install or upgrade of that formula.
func homebrewInstalls(dir string, since, until time.Time, emit func(event.Event)) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		fi, err := ent.Info()
		if err != nil || !inWindow(fi.ModTime(), since, until) {
			continue
		}
		e := event.Event{TS: fi.ModTime(), Source: "installs", Kind: event.KindInstall}
		e.Subject = event.Subject{Name: ent.Name()}
		e.Set("by", "brew")
		e.Set("via", "Homebrew logs")
		e.Approx = true // build or upgrade; the folder does not say which
		emit(e)
	}
	return nil
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
