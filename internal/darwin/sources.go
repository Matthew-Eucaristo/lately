package darwin

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/collect"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// PowerWindow is the shortest window that reads pmset. `pmset -g log` has
// no time filter and takes about 5 s, which would double the default view.
const PowerWindow = time.Hour

// Sources returns the default no-root sources for a home folder and window.
func Sources(home string, window time.Duration) []source.Source {
	reports := NewReports(home)
	installs := NewInstalls(home)
	out := []source.Source{
		reports, installs,
		&Persistence{Home: home},
		&Boots{Home: home, Reports: reports, Install: installs},
	}
	if window >= PowerWindow {
		out = append(out, Power{})
	}
	for _, l := range Lenses() {
		out = append(out, l)
	}
	return out
}

// LogReach is how far back the unified log really goes: the oldest file in
// the Persist store. `log stats` overstates it.
func LogReach() (time.Time, bool) {
	ents, err := os.ReadDir("/private/var/db/diagnostics/Persist")
	if err != nil {
		return time.Time{}, false
	}
	var times []time.Time
	for _, e := range ents {
		if filepath.Ext(e.Name()) != ".tracev3" {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		birth, mod := fileTimes(fi)
		if birth.IsZero() {
			birth = mod
		}
		times = append(times, birth)
	}
	if len(times) == 0 {
		return time.Time{}, false
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	return times[0], true
}

// Elevated reports whether lately runs as root.
func Elevated() bool { return os.Geteuid() == 0 }

// Ensure the elevated source satisfies the optional interface.
var _ source.Streamer = (*ESLogger)(nil)

// ProbeAll reports every source's capability.
func ProbeAll(ctx context.Context, srcs []source.Source) map[string]source.Capability {
	out := map[string]source.Capability{}
	for _, s := range srcs {
		out[s.ID()] = s.Probe(ctx)
	}
	return out
}

// FollowPoll is how often follow mode rereads sources without a live feed.
const FollowPoll = 5 * time.Second

// Followers are the live forms of the default sources: `log stream` for
// each lens, new crash report files, install records when they change, and
// a short poll of persistence files (a few directory reads). pmset (5 s per read) and boot records are not followed.
func Followers(srcs []source.Source) []source.Follower {
	var out []source.Follower
	for _, s := range srcs {
		switch s := s.(type) {
		case source.Follower:
			out = append(out, s)
		case *Persistence:
			out = append(out, collect.Poll(s, FollowPoll))
		}
	}
	return out
}

// Ensure the live sources can follow.
var (
	_ source.Follower = (*LogSource)(nil)
	_ source.Follower = (*Reports)(nil)
	_ source.Follower = (*Installs)(nil)
)
