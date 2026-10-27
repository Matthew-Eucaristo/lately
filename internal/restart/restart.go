// Package restart fuses boot evidence into one answer to "why did my Mac
// restart?". Apple silicon Macs do not log a shutdown cause code, so the
// verdict is built from what is left: the login records (wtmp), the panic
// breadcrumb and reports, shutdown-stall reports, recent updates and the
// last power log line.
package restart

import (
	"fmt"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

// Kinds of verdict. There is always exactly one.
const (
	Clean   = "clean"
	Update  = "update"
	Panic   = "panic"
	Stall   = "stall"
	Unknown = "unknown"
)

// Evidence is everything the verdict looks at. Zero values mean "not found";
// the *Known flags separate "not found" from "could not read".
type Evidence struct {
	Boot         time.Time `json:"boot"`
	PrevBoot     time.Time `json:"previous_boot,omitzero"`
	AppleSilicon bool      `json:"apple_silicon"`

	WtmpKnown      bool       `json:"wtmp_readable"`
	ShutdownBefore *time.Time `json:"shutdown_record,omitempty"` // between PrevBoot and Boot

	BreadcrumbKnown bool     `json:"breadcrumb_readable"`
	BreadcrumbPanic string   `json:"breadcrumb_panic,omitempty"`
	PanicReports    []string `json:"panic_reports,omitempty"`
	PanicLogLines   int      `json:"panic_log_lines,omitempty"`
	NoPanicLog      bool     `json:"dumppanic_found_none,omitempty"` // DumpPanic said it found no panic log
	Watchdog        bool     `json:"watchdog_reset,omitempty"`       // PMU boot faults name the watchdog
	StallReports    []string `json:"stall_reports,omitempty"`
	Updates         []string `json:"updates,omitempty"`

	LastPower     string    `json:"last_power_line,omitempty"`
	LastPowerTS   time.Time `json:"last_power_ts,omitzero"`
	PowerSource   string    `json:"power_source,omitempty"` // AC or Battery
	Charge        string    `json:"charge,omitempty"`
	ShutdownCause string    `json:"shutdown_cause,omitempty"` // Intel only

	LastWordsTS      time.Time `json:"last_log_ts,omitzero"`
	LastWordsProcess string    `json:"last_log_process,omitempty"`
}

// Check is one line of the restart view.
type Check struct {
	Found bool   `json:"found"`
	Name  string `json:"name"`
	Text  string `json:"text"`
	Note  string `json:"note,omitempty"`
}

// Verdict is the single answer.
type Verdict struct {
	Kind    string      `json:"kind"`
	Level   event.Level `json:"-"`
	Title   string      `json:"title"`
	Explain string      `json:"explanation"`
	Checks  []Check     `json:"checks"`
	Notes   []string    `json:"notes"`
	Approx  bool        `json:"inferred"`
}

// Decide builds the verdict.
func Decide(ev Evidence) Verdict {
	v := Verdict{Approx: ev.AppleSilicon}
	panicked := ev.BreadcrumbPanic != "" || len(ev.PanicReports) > 0 || ev.PanicLogLines > 0
	clean := ev.ShutdownBefore != nil
	stalled := len(ev.StallReports) > 0
	updated := len(ev.Updates) > 0
	hardware := hardwareCause(ev.ShutdownCause)

	switch {
	case panicked:
		v.Kind, v.Level = Panic, event.High
		v.Title = "Unexpected restart: kernel panic"
		v.Explain = "macOS crashed and restarted itself. Panics usually come from a kernel or system extension, a driver, or failing hardware."
	case stalled:
		v.Kind, v.Level = Stall, event.Medium
		v.Title = "Hung shutdown"
		v.Explain = "A shutdown or restart got stuck and macOS wrote a shutdown-stall report. An app or service that would not quit is the usual cause."
		if ev.Watchdog && !clean {
			v.Explain += " It never finished: the hardware watchdog reset the Mac."
		}
	case ev.Watchdog && !clean:
		v.Kind, v.Level = Unknown, event.Medium
		v.Title = "Unexpected restart: the Mac froze and the watchdog reset it"
		v.Explain = "There is no shutdown record and no panic, but the boot fault data names the hardware watchdog, which resets a Mac that stopped responding."
	case clean && updated:
		v.Kind, v.Level = Update, event.Info
		v.Title = "Restart for a software update"
		v.Explain = "The Mac shut down normally and a macOS update was installed around the restart."
	case clean:
		v.Kind, v.Level = Clean, event.Info
		v.Title = "Clean restart or shutdown"
		v.Explain = "macOS recorded a normal shutdown before this boot, so someone or something chose Restart or Shut Down."
	default:
		v.Kind, v.Level = Unknown, event.Medium
		v.Title = "Unexpected restart: cause unknown"
		switch {
		case hardware != "":
			v.Explain = "The shutdown cause code points to " + hardware + "."
		case ev.Charge != "" || ev.PowerSource == "Battery":
			v.Explain = "There is no shutdown record and no panic evidence. This Mac has a battery, so a power cut is unlikely: holding the power button, a freeze that was reset without a panic report, or a flat battery are the usual causes."
		default:
			v.Explain = "There is no shutdown record and no panic evidence. Loss of power is the most common cause; holding the power button looks the same."
		}
	}
	if !ev.WtmpKnown && v.Kind == Unknown {
		v.Explain = "The login records could not be read, so a clean shutdown cannot be told apart from an unexpected one."
		v.Approx = true
	}

	v.Checks = checks(ev)
	if ev.AppleSilicon {
		v.Notes = append(v.Notes, "No shutdown cause code: Apple silicon Macs do not log one, so this verdict is inferred from the evidence above.")
	}
	if !ev.BreadcrumbKnown {
		v.Notes = append(v.Notes, "The panic breadcrumb could not be read; panic evidence comes from reports and the log only.")
	}
	return v
}

func checks(ev Evidence) []Check {
	var cs []Check
	switch {
	case !ev.WtmpKnown:
		cs = append(cs, Check{Name: "wtmp", Text: "login records unreadable"})
	case ev.ShutdownBefore != nil:
		cs = append(cs, Check{Found: true, Name: "wtmp", Text: "shutdown recorded " + clock(*ev.ShutdownBefore) + ", boot " + clock(ev.Boot), Note: "clean"})
	default:
		cs = append(cs, Check{Found: true, Name: "wtmp", Text: "boot " + clock(ev.Boot) + " with no shutdown record before it", Note: "not a clean restart"})
	}
	panicText := "no panic breadcrumb, report or log line"
	var parts []string
	if ev.BreadcrumbPanic != "" {
		parts = append(parts, "breadcrumb names a panic log")
	}
	if n := len(ev.PanicReports); n > 0 {
		parts = append(parts, plural(n, "panic report"))
	}
	if ev.PanicLogLines > 0 {
		parts = append(parts, plural(ev.PanicLogLines, "panic log line"))
	}
	if len(parts) > 0 {
		panicText = strings.Join(parts, " · ")
	} else if ev.NoPanicLog {
		panicText = "DumpPanic checked after boot and found no panic log"
	}
	cs = append(cs, Check{Found: len(parts) > 0, Name: "panic", Text: panicText})
	if ev.Watchdog {
		cs = append(cs, Check{Found: true, Name: "watchdog", Text: "boot fault data records a watchdog reset (wdog)", Note: "the Mac stopped responding"})
	}
	if n := len(ev.StallReports); n > 0 {
		cs = append(cs, Check{Found: true, Name: "stall", Text: plural(n, "shutdown_stall report") + ": " + strings.Join(ev.StallReports, ", ")})
	} else {
		cs = append(cs, Check{Name: "stall", Text: "no shutdown_stall report"})
	}
	if n := len(ev.Updates); n > 0 {
		cs = append(cs, Check{Found: true, Name: "update", Text: strings.Join(ev.Updates, ", ")})
	} else {
		cs = append(cs, Check{Name: "update", Text: "no macOS update installed around the restart"})
	}
	power := "no power log line before the boot"
	if ev.LastPower != "" {
		power = "last line " + clock(ev.LastPowerTS) + ": " + ev.LastPower
	}
	note := ""
	switch {
	case ev.Charge != "":
		note = ev.PowerSource + ", charge " + ev.Charge + "%"
	case ev.PowerSource != "":
		note = ev.PowerSource
	}
	cs = append(cs, Check{Found: ev.LastPower != "", Name: "power", Text: power, Note: note})
	if ev.ShutdownCause != "" {
		cs = append(cs, Check{Found: true, Name: "cause", Text: "previous shutdown cause " + ev.ShutdownCause, Note: hardwareCause(ev.ShutdownCause)})
	}
	if !ev.LastWordsTS.IsZero() {
		cs = append(cs, Check{Found: true, Name: "last words", Text: clock(ev.LastWordsTS) + " last log entry before the gap (" + ev.LastWordsProcess + ")"})
	}
	return cs
}

// hardwareCause explains the Intel shutdown cause codes whose meaning is
// well established; others are shown as numbers only.
func hardwareCause(code string) string {
	switch code {
	case "5":
		return ""
	case "3":
		return "a forced shutdown (power button held)"
	case "0":
		return "a loss of power"
	}
	return ""
}

func clock(t time.Time) string {
	if t.IsZero() {
		return "?"
	}
	// t keeps its own zone: local for the terminal, UTC in shared JSON
	if y, m, d := time.Now().In(t.Location()).Date(); t.Year() == y && t.Month() == m && t.Day() == d {
		return t.Format("15:04:05") + " today"
	}
	return t.Format("Jan 2 15:04:05")
}

func plural(n int, s string) string {
	if n == 1 {
		return "1 " + s
	}
	return fmt.Sprintf("%d %ss", n, s)
}

// Clean returns a copy for sharing: times in UTC and every free-text field
// passed through red (a redactor's String method).
func (ev Evidence) Clean(red func(string) string) Evidence {
	utc := func(t time.Time) time.Time {
		if t.IsZero() {
			return t
		}
		return t.UTC()
	}
	ev.Boot, ev.PrevBoot, ev.LastPowerTS, ev.LastWordsTS = utc(ev.Boot), utc(ev.PrevBoot), utc(ev.LastPowerTS), utc(ev.LastWordsTS)
	if ev.ShutdownBefore != nil {
		t := ev.ShutdownBefore.UTC()
		ev.ShutdownBefore = &t
	}
	ev.BreadcrumbPanic = red(ev.BreadcrumbPanic)
	ev.LastPower, ev.LastWordsProcess = red(ev.LastPower), red(ev.LastWordsProcess)
	for _, list := range []*[]string{&ev.PanicReports, &ev.StallReports, &ev.Updates} {
		out := make([]string, len(*list))
		for i, v := range *list {
			out[i] = red(v)
		}
		if len(out) > 0 {
			*list = out
		}
	}
	return ev
}
