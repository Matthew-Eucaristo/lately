// Package report renders findings as timeline rows, event cards, Markdown
// and JSON, and decides the exit code. The TUI and the CLI share it.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/redact"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
)

// Exit codes, after witr: scripts can branch on them.
const (
	ExitClean    = 0 // nothing at or above the floor
	ExitWarning  = 1 // medium or high findings
	ExitCritical = 2 // at least one critical finding
	ExitPrivs    = 3 // the requested tier needs privileges lately does not have
	ExitError    = 4 // bad usage or every source failed
)

// SchemaVersion of --json output. It only grows within a version.
const SchemaVersion = 1

// Meta is everything about a run that is not a finding.
type Meta struct {
	Version       string
	Since, Until  time.Time
	Window        string
	Tier          string // user or elevated
	Floor         event.Level
	All           bool // show hidden rows too
	LogReach      time.Time
	Redactions    int
	Baseline      *baseline.Baseline
	Errors        map[string]error
	Notes         []string
	AppleSilicon  bool
	CaptureSince  time.Time
	SourcesFailed int
	SourcesTotal  int
	Replay        bool // sample data, not this Mac
}

// Limitations names every blind spot of this run in plain words.
func Limitations(m Meta) []string {
	var out []string
	if m.Replay {
		return []string{"Replayed sample data: these rows are examples, not events on this Mac.",
			"On a real Mac the same view names how far back the log reaches, what macOS redacted, and what needs sudo."}
	}
	if !m.LogReach.IsZero() {
		out = append(out, "The unified log reaches back to "+m.LogReach.Local().Format("Jan 2 15:04")+" ("+Ago(m.Until.Sub(m.LogReach))+"); older log events are gone.")
	} else {
		out = append(out, "How far back the unified log reaches is unknown; macOS keeps only a few days.")
	}
	if m.Redactions > 0 {
		out = append(out, fmt.Sprintf("%d field(s) were redacted by macOS as <private>.", m.Redactions))
	}
	if m.Tier != "elevated" {
		out = append(out, "Commands and parents of short-lived processes need capture: sudo lately capture")
		out = append(out, "Login items inside apps are only partly visible without sudo.")
	} else if !m.CaptureSince.IsZero() {
		out = append(out, "Capture started "+m.CaptureSince.Local().Format("15:04:05")+"; nothing before it is known. eslogger's format is not a stable API.")
	}
	if m.AppleSilicon {
		out = append(out, "Restart causes are inferred: Apple silicon Macs log no shutdown cause code.")
	}
	if m.Until.Sub(m.Since) < time.Hour {
		out = append(out, "Sleep and wake (pmset, about 5 s to read) are shown for windows of 1h or more.")
	}
	out = append(out, "Permission and Gatekeeper rows come from undocumented log text (≈ approximate).")
	out = append(out, "Connection history needs a firewall extension such as LuLu or Little Snitch; lately net shows live connections only.")
	return out
}

// Shown says whether a finding is displayed: it must reach the floor, and
// rows hidden as Apple or known appear only with All.
func Shown(f *rules.Finding, m Meta) bool {
	switch f.Hidden(m.Floor) {
	case "":
		return true
	case "below floor":
		return false
	}
	return m.All
}

// Counts returns shown findings per level and how many are not shown.
func Counts(fs []*rules.Finding, m Meta) (levels [5]int, hidden int) {
	for _, f := range fs {
		if !Shown(f, m) {
			hidden += f.Count
			continue
		}
		levels[f.Level] += f.Count
	}
	return levels, hidden
}

// Visible filters findings for display.
func Visible(fs []*rules.Finding, m Meta) []*rules.Finding {
	var out []*rules.Finding
	for _, f := range fs {
		if Shown(f, m) {
			out = append(out, f)
		}
	}
	return out
}

// ExitCode follows the scheme above for the visible findings.
func ExitCode(fs []*rules.Finding, m Meta) int {
	code := ExitClean
	for _, f := range Visible(fs, m) {
		switch {
		case f.Level == event.Critical:
			return ExitCritical
		case f.Level >= event.Medium:
			code = ExitWarning
		}
	}
	if m.SourcesTotal > 0 && m.SourcesFailed == m.SourcesTotal {
		return ExitError
	}
	return code
}

// Ago is a compact duration such as 2.1 days, 3h or 15m.
func Ago(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	case d >= time.Hour:
		return fmt.Sprintf("%.0fh", d.Hours())
	default:
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
}

// Who describes the subject's signer.
func Who(s event.Subject) string {
	switch s.Signer {
	case event.SignerApple:
		return "Apple"
	case event.SignerDevID:
		return "Developer ID " + s.TeamID
	case event.SignerAdhoc:
		return "ad-hoc signed"
	case event.SignerUnsigned:
		return "unsigned"
	}
	if s.TeamID != "" {
		return "team " + s.TeamID
	}
	if s.IsApple() {
		return "Apple (by name)"
	}
	return ""
}

// Flags are the short markers at the end of a row.
func Flags(f *rules.Finding) string {
	var fl []string
	if f.New {
		fl = append(fl, "NEW")
	}
	if f.Known {
		fl = append(fl, "known")
	}
	if f.Approx() {
		fl = append(fl, "≈approx")
	}
	return strings.Join(fl, " ")
}

// Section is one labelled block of a card.
type Section struct {
	Label string
	Lines []string
}

// Card builds the fixed card sections for a finding.
func Card(f *rules.Finding, r *redact.Redactor) []Section {
	e := f.Event
	red := r.String
	what := []string{red(rules.Expand(f.Rule.What, e))}
	if p := e.Subject.Path; p != "" && !strings.Contains(what[0], red(p)) {
		what = append(what, red(p))
	}
	who := []string{red(e.Subject.Label())}
	if w := Who(e.Subject); w != "" {
		who[0] += " · " + w
	}
	if a := e.Field("authority"); a != "" {
		who = append(who, red(a))
	}
	switch {
	case f.New:
		who = append(who, "first seen on this Mac")
	case f.Known:
		who = append(who, "marked known")
	}
	if e.Subject.PID != 0 {
		who = append(who, fmt.Sprintf("pid %d", e.Subject.PID))
	}
	why := f.Why
	if len(why) == 0 {
		why = []string{"The evidence does not say what caused it."}
	}
	if f.Count > 1 {
		why = append(why, fmt.Sprintf("Happened %d times, %s → %s", f.Count, e.TS.Local().Format("15:04:05"), f.Last.Local().Format("15:04:05")))
	}
	if s := e.Field("since"); s != "" {
		why = append(why, "Found by comparing with the baseline, "+s)
	}
	matters := []string{f.Rule.Matters}
	if len(f.Rule.MITRE) > 0 {
		matters = append(matters, "MITRE ATT&CK "+strings.Join(f.Rule.MITRE, ", "))
	}
	do := []string{red(rules.Expand(f.Rule.Do, e))}
	conf := "confidence ✓"
	if f.Approx() {
		conf = "confidence ≈ approximate"
	}
	src := fmt.Sprintf("%s · rule %s v%d · %s", e.Source, f.Rule.ID, rules.Version, conf)
	if len(f.Adjust) > 0 {
		src += " · " + strings.Join(f.Adjust, ", ")
	}
	raw := redAll(r, Raw(f))
	if len(raw) == 0 {
		raw = []string{"(no raw record for this source)"}
	}
	return []Section{
		{"WHAT", nonEmpty(what)},
		{"WHO", who},
		{"WHY", redAll(r, why)},
		{"MATTERS", matters},
		{"DO", do},
		{"RAW", raw},
		{"SOURCE", []string{src}},
	}
}

// Raw is where the evidence lives and how to see it yourself.
func Raw(f *rules.Finding) []string {
	e := f.Event
	var out []string
	for _, k := range []string{"plist", "file", "report_path"} {
		if v := e.Field(k); v != "" && v != e.Subject.Path {
			out = append(out, v)
		}
	}
	if p := e.Field("predicate"); p != "" {
		out = append(out, fmt.Sprintf("/usr/bin/log show --start '%s' --end '%s' --predicate '%s'",
			e.TS.Add(-time.Minute).Local().Format("2006-01-02 15:04:05"), f.Last.Add(time.Minute).Local().Format("2006-01-02 15:04:05"), p))
	}
	switch e.Source {
	case "pmset":
		out = append(out, "pmset -g log")
	case "boots":
		out = append(out, "lately why-restart · last reboot · last shutdown")
	}
	if e.Raw != "" {
		raw := strings.Join(strings.Fields(e.Raw), " ")
		if len(raw) > 400 {
			raw = raw[:399] + "…"
		}
		out = append(out, raw)
	}
	return out
}

func nonEmpty(ss []string) []string {
	var out []string
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func redAll(r *redact.Redactor, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = r.String(s)
	}
	return out
}

// RowText is a plain fixed-column timeline row.
func RowText(f *rules.Finding, r *redact.Redactor) string {
	row := fmt.Sprintf("%s  %s %-4s  %-8s  %s", f.Event.TS.Local().Format("15:04:05"), f.Level.Glyph(), f.Level.Short(),
		f.Rule.Category, r.String(f.Title))
	for _, s := range []string{r.String(Who(f.Event.Subject)), Flags(f)} {
		if s != "" {
			row += "  " + s
		}
	}
	return row
}

// Header is the one-line summary above a timeline.
func Header(fs []*rules.Finding, m Meta) string {
	lv, hidden := Counts(fs, m)
	return fmt.Sprintf("lately · last %s (%s) · tier %s · floor ≥%s   ✖ %d  ▲ %d  ● %d  ○ %d  · %d hidden",
		m.Window, Span(m.Since, m.Until), strings.ToUpper(m.Tier),
		m.Floor.Short(), lv[event.Critical], lv[event.High], lv[event.Medium], lv[event.Low]+lv[event.Info], hidden)
}

// Span is "14:47–15:02", with dates once the window passes 12 hours.
func Span(since, until time.Time) string {
	if until.Sub(since) > 12*time.Hour {
		return since.Local().Format("Jan 2 15:04") + " – " + until.Local().Format("Jan 2 15:04")
	}
	return since.Local().Format("15:04") + "–" + until.Local().Format("15:04")
}

// Text prints the CLI timeline.
func Text(w io.Writer, fs []*rules.Finding, m Meta, r *redact.Redactor) {
	fmt.Fprintln(w, Header(fs, m))
	fmt.Fprintln(w, strings.Repeat("─", 78))
	vis := Visible(fs, m)
	if len(vis) == 0 {
		fmt.Fprintf(w, "Nothing at %s or above. %s\n", m.Floor, hiddenHint(fs, m))
	}
	for _, f := range vis {
		fmt.Fprintln(w, RowText(f, r))
	}
	fmt.Fprintln(w, strings.Repeat("─", 78))
	for _, s := range footer(m) {
		fmt.Fprintln(w, "ⓘ "+r.String(s))
	}
}

func hiddenHint(fs []*rules.Finding, m Meta) string {
	if _, h := Counts(fs, m); h > 0 {
		return fmt.Sprintf("%d lower, Apple or known rows hidden; --min-level info --all shows them.", h)
	}
	return ""
}

func footer(m Meta) []string {
	out := Limitations(m)
	out = append(out, m.Notes...)
	for id, err := range m.Errors {
		out = append(out, "source "+id+": "+err.Error())
	}
	out = append(out, BaselineLine(m.Baseline))
	return out
}

// BaselineLine says where the baseline lives and how big it is.
func BaselineLine(b *baseline.Baseline) string {
	if b == nil || b.Status() == baseline.Disabled {
		return "Baseline off (--no-baseline): nothing is marked NEW and nothing is written."
	}
	size := ""
	if n := b.Size(); n >= 0 {
		size = fmt.Sprintf(" (%s)", byteSize(n))
	}
	switch b.Status() {
	case baseline.Fresh:
		return "First run: building the baseline, so nothing is marked NEW yet. File: " + b.Path() + "; remove with lately forget."
	case baseline.Corrupt:
		return b.Warning()
	}
	return "Baseline " + b.Path() + size + " · salted hashes only · lately forget removes it"
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// Markdown is the redacted export for pasting into an issue.
func Markdown(w io.Writer, fs []*rules.Finding, m Meta, r *redact.Redactor) {
	fmt.Fprintf(w, "# lately · last %s\n\n", m.Window)
	fmt.Fprintf(w, "%s\n\n", Header(fs, m))
	vis := Visible(fs, m)
	if len(vis) == 0 {
		fmt.Fprintf(w, "Nothing at %s or above. %s\n", m.Floor, hiddenHint(fs, m))
	} else {
		fmt.Fprintln(w, "| Time | Level | Category | What | Who | Flags |")
		fmt.Fprintln(w, "| --- | --- | --- | --- | --- | --- |")
	}
	for _, f := range vis {
		fmt.Fprintf(w, "| %s | %s %s | %s | %s | %s | %s |\n", f.Event.TS.Local().Format("15:04:05"), f.Level.Glyph(), f.Level.Short(),
			f.Rule.Category, md(r.String(f.Title)), md(r.String(Who(f.Event.Subject))), Flags(f))
	}
	fmt.Fprintln(w, "\n## Limitations")
	for _, s := range footer(m) {
		fmt.Fprintln(w, "- "+md(r.String(s)))
	}
	fmt.Fprintln(w, "\n_Redacted by lately: home, user and host names, serial, UUIDs, IPs and URL paths are placeholders._")
}

func md(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// JSON document types.
type jsonDoc struct {
	SchemaVersion int               `json:"schema_version"`
	Tool          jsonTool          `json:"tool"`
	Window        jsonWindow        `json:"window"`
	Tier          string            `json:"tier"`
	Floor         string            `json:"floor"`
	LogReach      *time.Time        `json:"log_reaches_back,omitempty"`
	Counts        map[string]int    `json:"counts"`
	Hidden        int               `json:"hidden"`
	Findings      []jsonFinding     `json:"findings"`
	Limitations   []string          `json:"limitations"`
	Notes         []string          `json:"notes,omitempty"`
	Errors        map[string]string `json:"errors,omitempty"`
	Baseline      jsonBaseline      `json:"baseline"`
	Redacted      bool              `json:"redacted"`
}

type jsonTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type jsonWindow struct {
	Since time.Time `json:"since"`
	Until time.Time `json:"until"`
}

type jsonBaseline struct {
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
}

type jsonFinding struct {
	ID          string              `json:"id"`
	TS          time.Time           `json:"ts"`
	Last        time.Time           `json:"last"`
	Count       int                 `json:"count"`
	Level       string              `json:"level"`
	Category    string              `json:"category"`
	Rule        string              `json:"rule"`
	MITRE       []string            `json:"mitre,omitempty"`
	Title       string              `json:"title"`
	FirstSeen   bool                `json:"first_seen"`
	Known       bool                `json:"known"`
	Approximate bool                `json:"approximate"`
	Source      string              `json:"source"`
	Subject     event.Subject       `json:"subject"`
	Fields      map[string]string   `json:"fields,omitempty"`
	Card        map[string][]string `json:"card"`
}

// JSON writes the machine-readable document. r == nil means unredacted.
func JSON(w io.Writer, fs []*rules.Finding, m Meta, r *redact.Redactor) error {
	lv, hidden := Counts(fs, m)
	doc := jsonDoc{SchemaVersion: SchemaVersion, Tool: jsonTool{"lately", m.Version},
		Window: jsonWindow{m.Since.UTC(), m.Until.UTC()}, Tier: m.Tier, Floor: m.Floor.String(), Hidden: hidden,
		Counts: map[string]int{}, Limitations: redAll(r, Limitations(m)), Notes: redAll(r, m.Notes), Redacted: r != nil,
		Findings: []jsonFinding{}}
	for l := event.Info; l <= event.Critical; l++ {
		doc.Counts[l.String()] = lv[l]
	}
	if !m.LogReach.IsZero() {
		t := m.LogReach.UTC()
		doc.LogReach = &t
	}
	if len(m.Errors) > 0 {
		doc.Errors = map[string]string{}
		for k, v := range m.Errors {
			doc.Errors[k] = r.String(v.Error())
		}
	}
	doc.Baseline = jsonBaseline{Status: baselineStatus(m.Baseline)}
	if m.Baseline != nil && m.Baseline.Status() != baseline.Disabled {
		doc.Baseline.Path = r.String(m.Baseline.Path())
	}
	for _, f := range Visible(fs, m) {
		sub := f.Event.Subject
		sub.Name, sub.Path, sub.Responsible = r.String(sub.Name), r.String(sub.Path), r.String(sub.Responsible)
		fields := map[string]string{}
		for k, v := range f.Event.Fields {
			fields[k] = r.String(v)
		}
		card := map[string][]string{}
		for _, s := range Card(f, r) {
			card[strings.ToLower(s.Label)] = s.Lines
		}
		doc.Findings = append(doc.Findings, jsonFinding{ID: f.ID, TS: f.Event.TS.UTC(), Last: f.Last.UTC(), Count: f.Count,
			Level: f.Level.String(), Category: f.Rule.Category, Rule: f.Rule.ID, MITRE: f.Rule.MITRE,
			Title: r.String(f.Title), FirstSeen: f.New, Known: f.Known, Approximate: f.Approx(),
			Source: f.Event.Source, Subject: sub, Fields: fields, Card: card})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func baselineStatus(b *baseline.Baseline) string {
	if b == nil {
		return "off"
	}
	return [...]string{"fresh", "loaded", "damaged", "off"}[b.Status()]
}
