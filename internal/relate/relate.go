// Package relate finds the findings that belong with another one: the same
// process, its parent or children, the app it acted for, other events of
// the same app or developer, the install that delivered it, and whatever
// else happened around the same time. The card lists them so an audit can
// follow a thread instead of scrolling the timeline.
package relate

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
)

// Reasons, strongest first. A finding is listed once, under the first
// reason that holds.
const (
	SameProcess = "same process"
	Parent      = "parent"
	Child       = "child"
	ActedFor    = "acted for"     // the app this event names as responsible
	OnBehalf    = "on its behalf" // events that name this one as responsible
	Program     = "launch item"   // persistence item ↔ the program it runs
	Install     = "install"
	SameApp     = "same app"
	SameDev     = "same developer"
	Nearby      = "around then"
)

// Order is the display order of the reasons.
var Order = []string{SameProcess, Parent, Child, ActedFor, OnBehalf, Program, Install, SameApp, SameDev, Nearby}

// Link is one related finding.
type Link struct {
	F      *rules.Finding
	Reason string
	Delta  time.Duration // other minus this
}

const (
	pidSpan  = 12 * time.Hour // pids are reused; trust a match only this close
	nearSpan = 2 * time.Minute
)

// Find returns the findings related to f, grouped by reason in Order and
// nearest first within a reason. near decides which unrelated findings
// count as "around then" (the UI passes the ones a person would see).
func Find(all []*rules.Finding, f *rules.Finding, near func(*rules.Finding) bool) []Link {
	if f == nil {
		return nil
	}
	e := f.Event
	var out []Link
	for _, o := range all {
		if o == f || o.ID == f.ID {
			continue
		}
		d := nearest(o, e.TS)
		if r := reason(e, o.Event, d); r != "" || near != nil && near(o) && abs(d) <= nearSpan {
			if r == "" {
				r = Nearby
			}
			out = append(out, Link{F: o, Reason: r, Delta: d})
		}
	}
	rank := map[string]int{}
	for i, r := range Order {
		rank[r] = i
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Reason != out[j].Reason {
			return rank[out[i].Reason] < rank[out[j].Reason]
		}
		return abs(out[i].Delta) < abs(out[j].Delta)
	})
	return out
}

// nearest is the offset from t to the closest occurrence of o (a grouped
// row has several).
func nearest(o *rules.Finding, t time.Time) time.Duration {
	best := o.Event.TS.Sub(t)
	for _, ts := range o.Times {
		if d := ts.Sub(t); abs(d) < abs(best) {
			best = d
		}
	}
	return best
}

func reason(e, o event.Event, delta time.Duration) string {
	s, t := e.Subject, o.Subject
	d := abs(delta)
	switch {
	case s.PID != 0 && s.PID == t.PID && d <= pidSpan && s.Label() == t.Label():
		return SameProcess
	case s.PPID != 0 && s.PPID == t.PID && d <= pidSpan:
		return Parent
	case s.PID != 0 && t.PPID == s.PID && d <= pidSpan:
		return Child
	case names(t, s.Responsible):
		return ActedFor
	case names(s, t.Responsible):
		return OnBehalf
	case runs(e, t) || runs(o, s):
		return Program
	case installed(e, o) || installed(o, e):
		return Install
	case s.Key() != "" && s.Key() == t.Key():
		return SameApp
	case s.TeamID != "" && s.TeamID == t.TeamID && !s.IsApple():
		return SameDev
	}
	return ""
}

// names reports whether ref (a responsible app as a bundle ID, path, name
// or pid) refers to subject s.
func names(s event.Subject, ref string) bool {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if ref == "" {
		return false
	}
	for _, n := range []string{s.Name, s.BundleID, s.Path, filepath.Base(s.Path)} {
		if n = strings.ToLower(n); n != "" && n != "." && (n == ref || n == filepath.Base(ref)) {
			return true
		}
	}
	return s.PID != 0 && ref == strconv.Itoa(s.PID)
}

// runs: e is a persistence item whose program is s.
func runs(e event.Event, s event.Subject) bool {
	p := e.Field("program")
	return e.Kind == event.KindPersist && p != "" && (p == s.Path || filepath.Base(p) == s.Name && s.Name != "")
}

// installed: in is an install that delivered o (by name, or o is a
// persistence or system-extension change written during it).
func installed(in, o event.Event) bool {
	if in.Kind != event.KindInstall || o.Kind == event.KindInstall {
		return false
	}
	if d := o.TS.Sub(in.TS); (o.Kind == event.KindPersist || o.Kind == event.KindSysext) && d >= -30*time.Second && d <= 2*time.Minute {
		return true
	}
	a, b := in.Subject, o.Subject
	return a.BundleID != "" && a.BundleID == b.BundleID || a.Name != "" && strings.EqualFold(a.Name, b.Name)
}

func abs(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Counts summarises links per reason, in Order.
func Counts(ls []Link) []string {
	n := map[string]int{}
	for _, l := range ls {
		n[l.Reason]++
	}
	var out []string
	for _, r := range Order {
		if n[r] > 0 {
			out = append(out, strconv.Itoa(n[r])+" "+r)
		}
	}
	return out
}
