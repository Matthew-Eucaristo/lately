// Package rules loads the YAML rule set and turns events into findings:
// it picks the first matching rule, adjusts severity for context (signer,
// first seen, Apple, acknowledged) within the rule's band, groups bursts,
// and links persistence to the install that caused it.
package rules

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

//go:embed data/rules.yaml
var builtin []byte

// Version is bumped when rule semantics change; cards print it.
const Version = 1

// Rule is one YAML entry. See data/rules.yaml for the field meanings.
type Rule struct {
	ID             string   `yaml:"id" json:"id"`
	Title          string   `yaml:"title" json:"-"`
	Category       string   `yaml:"category" json:"category"`
	Level          string   `yaml:"level" json:"-"`
	Min            string   `yaml:"min" json:"-"`
	Max            string   `yaml:"max" json:"-"`
	FirstSeen      string   `yaml:"first_seen" json:"-"`
	FirstSeenLevel string   `yaml:"first_seen_level" json:"-"`
	Tier           string   `yaml:"tier" json:"tier"`
	Approx         bool     `yaml:"approx" json:"-"`
	MITRE          []string `yaml:"mitre" json:"mitre,omitempty"`
	Burst          *Burst   `yaml:"burst" json:"-"`
	Match          Match    `yaml:"match" json:"-"`
	What           string   `yaml:"what" json:"-"`
	Matters        string   `yaml:"matters" json:"-"`
	Do             string   `yaml:"do" json:"-"`

	base, min, max, firstLevel event.Level
	within                     time.Duration
}

// Burst raises the level when a rule fires often for one subject.
type Burst struct {
	Count  int    `yaml:"count"`
	Within string `yaml:"within"`
	Level  string `yaml:"level"`
	level  event.Level
	within time.Duration
}

// Match selects events.
type Match struct {
	Kind   string              `yaml:"kind"`
	Fields map[string][]string `yaml:"fields"`
	Not    map[string][]string `yaml:"not"`
}

// Set is a loaded, validated rule set.
type Set struct{ Rules []*Rule }

// Builtin loads the embedded rules. They are tested, so an error is a bug.
func Builtin() *Set {
	s, err := Parse(builtin)
	if err != nil {
		panic(err)
	}
	return s
}

// Parse loads and validates rules. A bad rule is an error, never skipped.
func Parse(data []byte) (*Set, error) {
	var rs []*Rule
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, r := range rs {
		if r.ID == "" || ids[r.ID] {
			return nil, fmt.Errorf("rule %q: missing or duplicate id", r.ID)
		}
		ids[r.ID] = true
		var err error
		if r.base, err = event.ParseLevel(r.Level); err != nil {
			return nil, fmt.Errorf("rule %s: %w", r.ID, err)
		}
		r.min, r.max = r.base, r.base
		if r.Min != "" {
			if r.min, err = event.ParseLevel(r.Min); err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		if r.Max != "" {
			if r.max, err = event.ParseLevel(r.Max); err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		r.firstLevel = -1
		if r.FirstSeenLevel != "" {
			if r.firstLevel, err = event.ParseLevel(r.FirstSeenLevel); err != nil {
				return nil, fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		if r.Burst != nil {
			if r.Burst.level, err = event.ParseLevel(r.Burst.Level); err != nil {
				return nil, fmt.Errorf("rule %s burst: %w", r.ID, err)
			}
			if r.Burst.within, err = time.ParseDuration(r.Burst.Within); err != nil || r.Burst.Count < 2 {
				return nil, fmt.Errorf("rule %s: bad burst", r.ID)
			}
		}
		if r.FirstSeen != "" && r.FirstSeen != "only" {
			return nil, fmt.Errorf("rule %s: first_seen must be \"only\"", r.ID)
		}
		if r.Tier != "user" && r.Tier != "elevated" {
			return nil, fmt.Errorf("rule %s: tier must be user or elevated", r.ID)
		}
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("no rules")
	}
	if last := rs[len(rs)-1]; last.Match.Kind != "" || len(last.Match.Fields) != 0 || len(last.Match.Not) != 0 || last.FirstSeen != "" {
		return nil, fmt.Errorf("the last rule must match everything, so no event is dropped")
	}
	return &Set{Rules: rs}, nil
}

// Get returns a rule by id.
func (s *Set) Get(id string) *Rule {
	for _, r := range s.Rules {
		if r.ID == id {
			return r
		}
	}
	return nil
}

func (m Match) matches(e event.Event) bool {
	if m.Kind != "" && m.Kind != e.Kind {
		return false
	}
	for k, want := range m.Fields {
		if !oneOf(e.Field(k), want) {
			return false
		}
	}
	for k, bad := range m.Not {
		if oneOf(e.Field(k), bad) {
			return false
		}
	}
	return true
}

func oneOf(v string, list []string) bool {
	for _, w := range list {
		if w == v || w == "*" && v != "" {
			return true
		}
	}
	return false
}

// Context answers the baseline questions the engine asks.
type Context interface {
	FirstSeen(ruleID, subjectKey string) bool // true when never seen before
	Known(subjectKey string) bool             // acknowledged with `a`
}

// Finding is an event that a rule classified.
type Finding struct {
	ID      string        `json:"id"`
	Event   event.Event   `json:"event"`
	Rule    *Rule         `json:"rule"`
	Level   event.Level   `json:"-"`
	Title   string        `json:"title"`
	New     bool          `json:"first_seen,omitempty"`
	Known   bool          `json:"known,omitempty"`
	Count   int           `json:"count"`
	Last    time.Time     `json:"last"`
	Times   []time.Time   `json:"-"`
	Why     []string      `json:"why,omitempty"`
	Adjust  []string      `json:"adjustments,omitempty"`
	Related []event.Event `json:"-"`
}

// Approx reports whether the finding rests on fragile evidence.
func (f *Finding) Approx() bool { return f.Rule.Approx || f.Event.Approx }

// Hidden says why a finding is not shown at the default view, or "".
func (f *Finding) Hidden(floor event.Level) string {
	switch {
	case f.Level < floor:
		return "below floor"
	case f.Known:
		return "known"
	case f.Level < event.Medium && f.Event.Subject.IsApple():
		return "apple"
	}
	return ""
}

// Classify runs every event through the rules.
func (s *Set) Classify(events []event.Event, ctx Context) []*Finding {
	var out []*Finding
	for _, e := range events {
		if f := s.classify(e, ctx); f != nil {
			out = append(out, f)
		}
	}
	return out
}

func (s *Set) classify(e event.Event, ctx Context) *Finding {
	key := e.Subject.Key()
	for _, r := range s.Rules {
		if !r.Match.matches(e) {
			continue
		}
		first := ctx != nil && key != "" && ctx.FirstSeen(r.ID, key)
		if r.FirstSeen == "only" && !first {
			continue
		}
		f := &Finding{Event: e, Rule: r, Count: 1, Last: e.TS, Times: []time.Time{e.TS}, New: first}
		f.Known = ctx != nil && key != "" && ctx.Known(key)
		f.Level = r.adjust(f)
		f.Title = Expand(r.Title, e)
		f.ID = findingID(r.ID, key, e.TS)
		return f
	}
	return nil
}

func (r *Rule) adjust(f *Finding) event.Level {
	l := r.base
	sub := f.Event.Subject
	if f.New && r.firstLevel >= 0 {
		l = r.firstLevel
		f.Adjust = append(f.Adjust, "first seen")
	} else if f.New && r.FirstSeen == "" {
		l++
		f.Adjust = append(f.Adjust, "first seen +1")
	}
	if sub.Signer == event.SignerUnsigned || sub.Signer == event.SignerAdhoc || f.Event.Field("weak_signature") == "yes" {
		l++
		f.Adjust = append(f.Adjust, sub.Signer+" signature +1")
	}
	if sub.Signer == event.SignerApple {
		l--
		f.Adjust = append(f.Adjust, "Apple -1")
	}
	if f.Known {
		l--
		f.Adjust = append(f.Adjust, "marked known -1")
	}
	lo, hi := r.min, r.max
	if r.firstLevel > hi {
		hi = r.firstLevel
	}
	return max(lo, min(hi, l))
}

func findingID(rule, key string, ts time.Time) string {
	h := sha256.Sum256([]byte(rule + "\x00" + key + "\x00" + ts.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(h[:4])
}

var placeholder = regexp.MustCompile(`\{(\w+)\}`)

// Expand fills {placeholders} from the event. Missing values collapse.
func Expand(tmpl string, e event.Event) string {
	s := placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		k := m[1 : len(m)-1]
		switch k {
		case "name":
			return e.Subject.Label()
		case "path":
			return e.Subject.Path
		case "bundle":
			return e.Subject.BundleID
		case "team":
			return e.Subject.TeamID
		case "kind":
			return e.Kind
		case "pid":
			if e.Subject.PID == 0 {
				return "?"
			}
			return strconv.Itoa(e.Subject.PID)
		}
		return e.Field(k)
	})
	s = strings.ReplaceAll(s, "()", "")
	s = strings.Join(strings.Fields(s), " ")
	return strings.TrimSuffix(strings.TrimSuffix(s, ":"), " ")
}

// Group merges findings with the same rule and subject that happen within
// ten minutes of each other (or the rule's burst window) into one row with
// a count, and applies burst levels.
func Group(fs []*Finding) []*Finding {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Event.TS.Before(fs[j].Event.TS) })
	open := map[string]*Finding{}
	var out []*Finding
	for _, f := range fs {
		k := f.Rule.ID + "\x00" + f.Event.Subject.Key() + "\x00" + f.Title
		window := 10 * time.Minute
		if f.Rule.Burst != nil && f.Rule.Burst.within > window {
			window = f.Rule.Burst.within
		}
		if g, ok := open[k]; ok && f.Event.TS.Sub(g.Event.TS) <= window {
			g.Count++
			g.Last = f.Event.TS
			g.Times = append(g.Times, f.Event.TS)
			g.Related = append(g.Related, f.Event)
			g.New = g.New || f.New
			g.Level = max(g.Level, f.Level)
			continue
		}
		open[k] = f
		out = append(out, f)
	}
	for _, g := range out {
		if b := g.Rule.Burst; b != nil && maxWithin(g.Times, b.within) >= b.Count && b.level > g.Level {
			g.Level = b.level
			g.Adjust = append(g.Adjust, fmt.Sprintf("×%d within %s", g.Count, b.Within))
		}
		if g.Count > 1 {
			g.Title += fmt.Sprintf(" ×%d", g.Count)
		}
	}
	return out
}

// maxWithin is the most times (sorted) that fall inside any span of d.
func maxWithin(ts []time.Time, d time.Duration) int {
	best, j := 0, 0
	for i := range ts {
		for ts[i].Sub(ts[j]) > d {
			j++
		}
		best = max(best, i-j+1)
	}
	return best
}

// Correlate adds "Why" lines from nearby events: the install that wrote a
// persistence item, the app that owns a launch, the crash details.
func Correlate(fs []*Finding) {
	var installs []*Finding
	for _, f := range fs {
		if f.Event.Kind == event.KindInstall {
			installs = append(installs, f)
		}
	}
	for _, f := range fs {
		e := f.Event
		switch e.Kind {
		case event.KindPersist, event.KindSysext:
			for _, in := range installs {
				d := e.TS.Sub(in.Event.TS)
				if d >= -30*time.Second && d <= 2*time.Minute {
					f.Why = append(f.Why, fmt.Sprintf("Written during the %s install (%s, %s)",
						in.Event.Subject.Label(), in.Event.Field("by"), in.Event.TS.Local().Format("15:04:05")))
				}
			}
			if e.Subject.Responsible != "" {
				f.Why = append(f.Why, "Added by "+e.Subject.Responsible)
			}
		case event.KindLaunch:
			if e.Subject.Responsible != "" {
				f.Why = append(f.Why, "Started on behalf of "+e.Subject.Responsible)
			}
		case event.KindCrash:
			if x := e.Field("termination"); x != "" {
				f.Why = append(f.Why, "Termination: "+x)
			}
			if p := e.Field("parent"); p != "" {
				f.Why = append(f.Why, "Parent: "+p)
			}
		case event.KindPermit:
			if e.Subject.Responsible != "" {
				f.Why = append(f.Why, "Responsible app: "+e.Subject.Responsible)
			}
			if h := e.Field("how"); h != "" {
				f.Why = append(f.Why, "Decision: "+h)
			}
		}
	}
}

// Sort orders findings newest first.
func Sort(fs []*Finding) {
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Event.TS.After(fs[j].Event.TS) })
}

// Process is the whole pipeline: classify, group bursts, correlate, sort
// newest first.
func (s *Set) Process(events []event.Event, ctx Context) []*Finding {
	fs := Group(s.Classify(events, ctx))
	Correlate(fs)
	Sort(fs)
	return fs
}
