package darwin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"howett.net/plist"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/restart"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Boots reads boot and shutdown records and, for each boot in the window,
// emits the restart verdict as an event.
type Boots struct {
	Home    string
	Reports *Reports
	Install *Installs
}

func (b *Boots) ID() string        { return "boots" }
func (b *Boots) Tier() source.Tier { return source.TierUser }
func (b *Boots) Probe(context.Context) source.Capability {
	return source.Capability{Available: true}
}

func (b *Boots) History(ctx context.Context, since, until time.Time, emit func(event.Event)) error {
	boots, err := BootTimes(ctx)
	if err != nil {
		return err
	}
	for i, t := range boots {
		if !inWindow(t, since, until) {
			continue
		}
		ev := b.Evidence(ctx, boots, i, false)
		v := restart.Decide(ev)
		e := event.Event{TS: t, Source: "boots", Kind: event.KindBoot, Approx: v.Approx}
		e.Subject = event.Subject{Name: "macOS", Signer: event.SignerApple}
		e.Set("verdict", v.Kind)
		e.Set("verdict_title", v.Title)
		e.Set("explain", v.Explain)
		emit(e)
	}
	return nil
}

// BootTimes returns boots newest first: the precise current boot from
// kern.boottime, then earlier ones from wtmp (minute precision).
func BootTimes(ctx context.Context) ([]time.Time, error) {
	cur, err := currentBoot(ctx)
	if err != nil {
		return nil, err
	}
	out := []time.Time{cur}
	reboots, _, err := Wtmp(ctx)
	if err != nil {
		return out, nil
	}
	for _, t := range reboots {
		if t.Before(cur.Add(-2 * time.Minute)) {
			out = append(out, t)
		}
	}
	return out, nil
}

var bootSec = regexp.MustCompile(`sec = (\d+)`)

func currentBoot(ctx context.Context) (time.Time, error) {
	out, err := runCmd(ctx, "/usr/sbin/sysctl", "-n", "kern.boottime")
	if err != nil {
		return time.Time{}, err
	}
	m := bootSec.FindSubmatch(out)
	if m == nil {
		return time.Time{}, errUnparsed("kern.boottime")
	}
	n, _ := strconv.ParseInt(string(m[1]), 10, 64)
	return time.Unix(n, 0), nil
}

type errUnparsed string

func (e errUnparsed) Error() string { return "could not parse " + string(e) }

// Wtmp returns reboot and shutdown times from `last`, newest first.
func Wtmp(ctx context.Context) (reboots, shutdowns []time.Time, err error) {
	r, err := runCmd(ctx, "/usr/bin/last", "reboot")
	if err != nil {
		return nil, nil, err
	}
	s, err := runCmd(ctx, "/usr/bin/last", "shutdown")
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	return ParseLast(bytes.NewReader(r), "reboot", now), ParseLast(bytes.NewReader(s), "shutdown", now), nil
}

var lastLine = regexp.MustCompile(`^(reboot|shutdown)\s+time\s+(\w{3} \w{3}\s+\d+ \d{2}:\d{2})`)

// ParseLast reads `last reboot|shutdown` output. It has no year, so years
// are inferred walking back from now (records are newest first).
func ParseLast(r io.Reader, kind string, now time.Time) []time.Time {
	var out []time.Time
	year := now.Year()
	limit := now.Add(24 * time.Hour)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		m := lastLine.FindStringSubmatch(sc.Text())
		if m == nil || m[1] != kind {
			continue
		}
		// Walk back from the current year to the first year in which the
		// date exists (Feb 29) and is not in the future.
		var t time.Time
		stamp := strings.Join(strings.Fields(m[2]), " ")
		for y := year; y > year-8 && t.IsZero(); y-- {
			p, err := time.ParseInLocation("Mon Jan 2 15:04 2006", stamp+" "+strconv.Itoa(y), time.Local)
			if err != nil || p.After(limit) {
				continue
			}
			t, year = p, y
		}
		if t.IsZero() {
			continue
		}
		out = append(out, t)
		limit = t.Add(time.Minute)
	}
	return out
}

// Breadcrumb is the panic breadcrumb DumpPanic writes: a dict from boot
// session UUID to the panic log path, empty when that boot had no panic.
const Breadcrumb = "/var/db/com.apple.DumpPanic.panicLogPathBreadcrumb"

// ReadBreadcrumb parses the breadcrumb plist.
func ReadBreadcrumb(r io.ReadSeeker) (map[string]string, error) {
	m := map[string]string{}
	err := plist.NewDecoder(r).Decode(&m)
	return m, err
}

var powerOnce struct {
	sync.Once
	data *PowerLogData
	err  error
}

// cachedPowerLog runs pmset at most once per process (it takes seconds).
func cachedPowerLog(ctx context.Context) (*PowerLogData, error) {
	powerOnce.Do(func() { powerOnce.data, powerOnce.err = PowerLog(ctx) })
	return powerOnce.data, powerOnce.err
}

// Evidence gathers what restart.Decide needs for boots[i]. lastWords adds
// a short unfiltered log query for the last entry before the gap (slow,
// used by the restart view only).
func (b *Boots) Evidence(ctx context.Context, boots []time.Time, i int, lastWords bool) restart.Evidence {
	ev := restart.Evidence{Boot: boots[i], AppleSilicon: runtime.GOARCH == "arm64" || appleSilicon(ctx)}
	if i+1 < len(boots) {
		ev.PrevBoot = boots[i+1]
	}
	// Evidence windows never reach into the neighbouring boots.
	next := time.Now()
	if i > 0 {
		next = boots[i-1]
	}
	before := func(t time.Time) time.Time { // clamp a window start to after PrevBoot
		if !ev.PrevBoot.IsZero() && t.Before(ev.PrevBoot) {
			return ev.PrevBoot
		}
		return t
	}
	after := func(t time.Time) time.Time { // clamp a window end to before the next boot
		if t.After(next) {
			return next
		}
		return t
	}
	if _, shutdowns, err := Wtmp(ctx); err == nil {
		ev.WtmpKnown = true
		for _, s := range shutdowns { // newest first
			if !s.After(ev.Boot) && s.After(ev.PrevBoot) {
				ev.ShutdownBefore = &s
				break
			}
		}
	}
	if i == 0 {
		if f, err := os.Open(Breadcrumb); err == nil {
			if m, err := ReadBreadcrumb(f); err == nil {
				ev.BreadcrumbKnown = true
				if id, err := runCmd(ctx, "/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"); err == nil {
					ev.BreadcrumbPanic = m[strings.TrimSpace(string(id))]
				}
			}
			f.Close()
		}
	} else {
		ev.BreadcrumbKnown = true // older boots are covered by reports only
	}
	// Panic reports and DumpPanic's check are written just after the boot;
	// a stall report is named for the stalled shutdown, just before it.
	from, to := before(ev.Boot.Add(-5*time.Minute)), after(ev.Boot.Add(30*time.Minute))
	stallFrom, stallTo := before(ev.Boot.Add(-30*time.Minute)), after(ev.Boot.Add(time.Minute))
	if b.Reports != nil {
		_ = b.Reports.History(ctx, min2(from, stallFrom), to, func(e event.Event) {
			switch e.Field("report_kind") {
			case "panic":
				if inWindow(e.TS, from, to) {
					ev.PanicReports = append(ev.PanicReports, e.Field("file"))
				}
			case "stall":
				if inWindow(e.TS, stallFrom, stallTo) {
					ev.StallReports = append(ev.StallReports, e.Field("file"))
				}
			}
		})
	}
	if b.Install != nil {
		_ = b.Install.History(ctx, before(ev.Boot.Add(-2*time.Hour)), to, func(e event.Event) {
			// Only macOS itself counts; XProtect and other data updates also
			// come from softwareupdated but restart nothing.
			if strings.Contains(e.Subject.Name, "macOS") {
				ev.Updates = append(ev.Updates, strings.TrimSpace(e.Subject.Name+" "+e.Field("version")))
			}
		})
	}
	if pl, err := cachedPowerLog(ctx); err == nil {
		if l, ok := pl.Before(ev.Boot.Add(-time.Second)); ok && (ev.PrevBoot.IsZero() || l.TS.After(ev.PrevBoot)) {
			ev.LastPowerTS, ev.LastPower = l.TS, shorten(l.Type+" "+l.Details, 60)
			if l.Type == "Assertions" {
				ev.LastPower = "power assertion activity (the Mac was awake)"
			}
		}
		ev.PowerSource, ev.Charge = pl.SourceBefore(ev.Boot)
	}
	panicLens := LensByName("panic")
	_ = panicLens.History(ctx, ev.Boot, after(ev.Boot.Add(10*time.Minute)), func(e event.Event) {
		switch e.Field("evidence") {
		case "panic":
			ev.PanicLogLines++
		case "no_panic":
			ev.NoPanicLog = true
		case "watchdog":
			ev.Watchdog = true
		}
	})
	if lastWords {
		ev.LastWordsTS, ev.LastWordsProcess = lastLogBefore(ctx, ev.Boot)
	}
	return ev
}

func appleSilicon(ctx context.Context) bool {
	out, err := runCmd(ctx, "/usr/sbin/sysctl", "-n", "hw.optional.arm64")
	return err == nil && strings.TrimSpace(string(out)) == "1"
}

// lastLogBefore finds the newest log record from before the boot. Only the
// time and process name are kept.
func lastLogBefore(ctx context.Context, boot time.Time) (time.Time, string) {
	out, err := runCmd(ctx, LogPath, "show", "--style", "ndjson",
		"--start", boot.Add(-3*time.Minute).Local().Format(localTime),
		"--end", boot.Add(-time.Second).Local().Format(localTime))
	if err != nil && len(out) == 0 {
		return time.Time{}, ""
	}
	var last time.Time
	var proc string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Timestamp == "" {
			continue
		}
		if r.ProcessImagePath == "" {
			continue
		}
		if t, err := r.Time(); err == nil && t.After(last) {
			last, proc = t, filepath.Base(r.ProcessImagePath)
		}
	}
	return last, proc
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func min2(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
