package ui

import (
	"fmt"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Matthew-Eucaristo/lately/internal/baseline"
	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/report"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
)

// Plain ANSI colours so the terminal theme decides the shades, as in fell.
// Every level also has a glyph and a word, so nothing depends on colour;
// Bubble Tea's colour profile honours NO_COLOR.
var (
	brand   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("2")).Padding(0, 1)
	bold    = lipgloss.NewStyle().Bold(true)
	faint   = lipgloss.NewStyle().Faint(true)
	cyan    = lipgloss.NewStyle().Foreground(lipgloss.Color("6"))
	green   = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	yellow  = lipgloss.NewStyle().Foreground(lipgloss.Color("3"))
	red     = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	magenta = lipgloss.NewStyle().Foreground(lipgloss.Color("5"))
	heading = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	cursorC = green.Render("▌")
	sep     = faint.Render("  ·  ")
)

func levelStyle(l event.Level) lipgloss.Style {
	switch l {
	case event.Critical:
		return red.Bold(true)
	case event.High:
		return red
	case event.Medium:
		return yellow
	case event.Low:
		return cyan
	}
	return faint
}

const (
	detailRows = 5
	// header, status, column header, separator, detail, separator, note, help
	chromeLines = 7 + detailRows
)

func (m *Model) bodyHeight() int { return max(3, m.height-chromeLines) }

func (m *Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "lately"
	return v
}

func (m *Model) render() string {
	var b strings.Builder
	line := func(s string) { b.WriteString(ansi.Truncate(s, m.width, "…") + "\n") }
	switch m.view {
	case cardView:
		for _, l := range m.cardLines() {
			line(l)
		}
		return strings.TrimSuffix(b.String(), "\n")
	case restartView, ancestryView, netView, exportView, helpView:
		return m.pageView()
	}
	line(m.header())
	line(m.statusLine())
	rs := m.rows()
	tw := m.titleWidth(rs)
	body := m.bodyHeight()
	if len(rs) > 0 {
		line(faint.Render(m.columns(tw)))
	} else {
		line("")
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+body {
		m.offset = m.cursor - body + 1
	}
	m.offset = max(0, min(m.offset, max(0, len(rs)-body)))
	var lines []string
	if len(rs) == 0 {
		lines = m.emptyLines()
	}
	for i := m.offset; i < min(len(rs), m.offset+body); i++ {
		lines = append(lines, m.row(rs[i], i == m.cursor, tw))
	}
	for i := range body {
		if i < len(lines) {
			line(lines[i])
		} else {
			line("")
		}
	}
	line(faint.Render(strings.Repeat("─", max(0, m.width))))
	detail := m.detail(m.current(rs))
	for i := range detailRows {
		if i < len(detail) {
			line(detail[i])
		} else {
			line("")
		}
	}
	line(faint.Render(strings.Repeat("─", max(0, m.width))))
	line(m.note())
	b.WriteString(ansi.Truncate(m.help(), m.width, "…"))
	return b.String()
}

// pageView renders the full-screen views (restart, ancestry, net, export, help).
func (m *Model) pageView() string {
	var b strings.Builder
	line := func(s string) { b.WriteString(ansi.Truncate(s, m.width, "…") + "\n") }
	title := map[view]string{restartView: "Why did my Mac restart?", ancestryView: "Process ancestry",
		netView: "Live network", exportView: "Export preview (redacted Markdown)", helpView: "Help"}[m.view]
	line(" " + brand.Render("lately") + " " + bold.Render(title))
	line("")
	lines := m.lines
	if m.view == helpView {
		lines = m.helpLines()
	}
	if m.view == restartView && len(lines) > 1 && strings.HasPrefix(lines[0], title) {
		lines = lines[1:] // the title is already the heading
	}
	var wrapped []string
	for _, l := range lines {
		wrapped = append(wrapped, wrap(l, m.width-2)...)
	}
	for i, l := range wrapped {
		if i >= m.height-4 {
			line(faint.Render(" …"))
			break
		}
		line(" " + l)
	}
	line("")
	keys := "esc back  q quit"
	if m.view == exportView {
		keys = "w save to current folder  y copy  " + keys
	}
	if m.view == netView && m.cfg.NoNet == "" {
		keys = "r refresh  " + keys
	}
	if m.status != "" {
		keys = green.Render(m.status) + "   " + keys
	}
	b.WriteString(ansi.Truncate(" "+faint.Render(keys), m.width, "…"))
	return b.String()
}

// header: brand and tier badge, window, counts, hidden, log reach.
func (m *Model) header() string {
	tier := green.Render("● user")
	switch {
	case m.cfg.Capture != nil:
		tier = magenta.Render("● elevated")
	case m.meta.Replay:
		tier = yellow.Render("● sample data")
	}
	lv, hidden := report.Counts(m.findings, m.meta)
	counts := strings.Join([]string{
		levelStyle(event.Critical).Render(fmt.Sprintf("✖ %d", lv[event.Critical])),
		levelStyle(event.High).Render(fmt.Sprintf("▲ %d", lv[event.High])),
		levelStyle(event.Medium).Render(fmt.Sprintf("● %d", lv[event.Medium])),
		levelStyle(event.Low).Render(fmt.Sprintf("○ %d", lv[event.Low])),
	}, " ")
	parts := []string{brand.Render("lately") + " " + tier,
		bold.Render("last "+m.meta.Window) + faint.Render(" ("+report.Span(m.meta.Since, m.meta.Until)+")"),
		counts, faint.Render(fmt.Sprintf("%d hidden", hidden+lv[event.Info]))}
	if !m.meta.LogReach.IsZero() {
		parts = append(parts, faint.Render("log reaches back "+report.Ago(time.Since(m.meta.LogReach))))
	}
	return " " + strings.Join(parts, sep)
}

func (m *Model) statusLine() string {
	switch {
	case m.filtering:
		return " filter: " + m.filter + "▏"
	case m.status != "":
		return " " + green.Render(m.status)
	case m.loading:
		names := make([]string, 0, len(m.pending))
		for id := range m.pending {
			names = append(names, id)
		}
		slices.Sort(names)
		return " " + faint.Render(fmt.Sprintf("reading %d of %d sources: %s…", len(names), len(m.cfg.Sources), strings.Join(names, ", ")))
	case m.filter != "":
		return " " + faint.Render("filter: "+m.filter+"  (/ to change)")
	}
	return ""
}

// Column widths. The title takes what is left.
const (
	colTime  = 8
	colLevel = 6
	colCat   = 8
	colWho   = 24
)

// titleWidth fits the longest visible title, within what the terminal
// leaves after the fixed columns (and WHO when it fits).
func (m *Model) titleWidth(rs []row) int {
	room := m.width - (3 + colTime + 2 + colLevel + 2 + colCat + 2 + 2 + 14)
	if m.showWho() {
		room -= colWho + 2
	}
	longest := 0
	for _, r := range rs {
		if r.f != nil {
			longest = max(longest, ansi.StringWidth(m.cfg.Redactor.String(r.f.Title)))
		}
	}
	return max(16, min(room, longest))
}

func (m *Model) showWho() bool { return m.width >= 100 }

func (m *Model) columns(tw int) string {
	c := fmt.Sprintf("   %-*s  %-*s  %-*s  %-*s", colTime, "TIME", colLevel, "LEVEL", colCat, "WHAT", tw, "")
	if m.showWho() {
		c += fmt.Sprintf("  %-*s", colWho, "WHO")
	}
	return c + fmt.Sprintf("  floor ≥%s · by %s", m.meta.Floor.Short(), m.group)
}

func (m *Model) emptyLines() []string {
	if m.loading {
		return []string{"", "   " + faint.Render("Reading the log, crash reports, power, boot and install records…")}
	}
	_, hidden := report.Counts(m.findings, m.meta)
	return []string{"", "   " + green.Render("Nothing at "+m.meta.Floor.String()+" or above in the last "+m.meta.Window+"."),
		"   " + faint.Render(fmt.Sprintf("%d lower or Apple rows are hidden: s lowers the floor, S shows hidden rows, t widens the window.", hidden))}
}

func (m *Model) row(r row, cur bool, tw int) string {
	if r.f == nil {
		return "   " + heading.Render(r.header)
	}
	f := r.f
	prefix := " "
	if cur {
		prefix = cursorC
	}
	lvl := levelStyle(f.Level).Render(fmt.Sprintf("%s %-4s", f.Level.Glyph(), f.Level.Short()))
	title := fit(m.cfg.Redactor.String(f.Title), tw)
	if cur || f.Level >= event.High {
		title = bold.Render(title)
	}
	out := fmt.Sprintf("%s  %s  %s  %-*s  %s", prefix, f.Event.TS.Local().Format("15:04:05"), lvl, colCat, f.Rule.Category, title)
	if m.showWho() {
		out += "  " + faint.Render(fit(m.cfg.Redactor.String(report.Who(f.Event.Subject)), colWho))
	}
	return out + "  " + m.flags(f)
}

func (m *Model) flags(f *rules.Finding) string {
	var parts []string
	if f.New {
		parts = append(parts, magenta.Render("NEW"))
	}
	if f.Known {
		parts = append(parts, faint.Render("known"))
	}
	if f.Approx() {
		parts = append(parts, faint.Render("≈approx"))
	}
	return strings.Join(parts, " ")
}

// detail is a short card for the row under the cursor.
func (m *Model) detail(f *rules.Finding) []string {
	if f == nil {
		return nil
	}
	red := m.cfg.Redactor
	e := f.Event
	pad := "  "
	head := pad + levelStyle(f.Level).Render(f.Level.Glyph()+" "+f.Level.Short()) + "  " + bold.Render(red.String(f.Title)) +
		faint.Render("  "+e.TS.Local().Format("15:04:05")+" · rule "+f.Rule.ID)
	out := []string{head}
	if what := red.String(rules.Expand(f.Rule.What, e)); what != "" {
		out = append(out, pad+what)
	}
	for _, w := range f.Why {
		out = append(out, pad+faint.Render("why: ")+red.String(w))
		break
	}
	out = append(out, pad+faint.Render("do:  ")+red.String(rules.Expand(f.Rule.Do, e)))
	out = append(out, pad+faint.Render("⏎ full card: who, why it matters, raw evidence and source"))
	return out
}

// note is the one limitation that matters most right now; ? lists all.
func (m *Model) note() string {
	var n string
	switch {
	case len(m.meta.Errors) > 0:
		return " " + red.Render(fmt.Sprintf("ⓘ %d source(s) failed: ? shows why", len(m.meta.Errors)))
	case m.meta.Replay:
		n = "Sample data, not this Mac · ? lists what lately cannot see"
	case m.cfg.Capture != nil:
		n = fmt.Sprintf("Capture since %s · %d processes · nothing before it is known", m.meta.CaptureSince.Local().Format("15:04:05"), m.tree.Len())
		if m.capNote != "" {
			n += " · " + m.capNote
		}
	case m.cfg.Baseline != nil && m.cfg.Baseline.Status() == baseline.Fresh:
		n = "First run: building the baseline, so nothing is marked NEW yet · ? lists what lately cannot see"
	default:
		n = "Short-lived commands need sudo lately capture · no network history · ? lists what lately cannot see"
	}
	return " " + faint.Render("ⓘ "+n)
}

func (m *Model) help() string {
	keys := []string{"↑↓ move", "⏎ card", "n next ≥MED", "s floor", "t window", "/ filter", "a known", "R restart", "A ancestry", "c net", "e export", "? help", "q quit"}
	return " " + faint.Render(strings.Join(keys, "  "))
}

// fit pads or truncates s to exactly w cells.
func fit(s string, w int) string {
	return pad(ansi.Truncate(s, w, "…"), w)
}

func (m *Model) cardLines() []string {
	f := m.current(m.rows())
	if f == nil {
		return []string{"No row selected.", faint.Render("esc back")}
	}
	w := max(40, min(m.width, 110))
	inner := w - 4
	top := fmt.Sprintf("┌ %s %s · %s · %s ", f.Level.Glyph(), f.Level.Short(), f.Rule.Category, m.cfg.Redactor.String(f.Title))
	stamp := " " + f.Event.TS.Local().Format("15:04:05") + " ┐"
	top = ansi.Truncate(top, w-ansi.StringWidth(stamp)-1, "…")
	top += strings.Repeat("─", max(0, w-ansi.StringWidth(top)-ansi.StringWidth(stamp))) + stamp
	out := []string{levelStyle(f.Level).Render(top)}
	for _, s := range report.Card(f, m.cfg.Redactor) {
		if s.Label == "RAW" && !m.showRaw && len(s.Lines) > 2 {
			s.Lines = append(s.Lines[:2:2], faint.Render("(r: show full raw record)"))
		}
		first := true
		for _, l := range s.Lines {
			for _, wl := range wrap(l, inner-10) {
				label := ""
				if first {
					label = s.Label
					first = false
				}
				out = append(out, "│ "+heading.Render(fmt.Sprintf("%-8s", label))+" "+pad(wl, inner-9)+" │")
			}
		}
	}
	bottom := " a mark known · A ancestry · R restart · e export · esc back ─┘"
	out = append(out, "└"+strings.Repeat("─", max(0, w-1-ansi.StringWidth(bottom)))+bottom)
	if m.status != "" {
		out = append(out, green.Render(m.status))
	}
	return out
}

func (m *Model) helpLines() []string {
	out := []string{bold.Render("What lately cannot see"), ""}
	for _, l := range report.Limitations(m.meta) {
		out = append(out, "• "+m.cfg.Redactor.String(l))
	}
	for _, n := range m.meta.Notes {
		out = append(out, "• "+m.cfg.Redactor.String(n))
	}
	for id, err := range m.meta.Errors {
		out = append(out, red.Render("• source "+id+": "+m.cfg.Redactor.String(err.Error())))
	}
	out = append(out, "", bold.Render("Levels"), "",
		"✖ CRIT act now · ▲ HIGH investigate one occurrence · ● MED look if unexpected · ○ LOW context · · INFO hidden by default",
		"Apple-signed rows below MED and rows marked known are hidden; S shows them.",
		"NEW = first seen on this Mac (salted-hash baseline) · ≈approx = inferred from undocumented log text",
		"", bold.Render("Keys"), "",
		"↑↓/jk move · ⏎ card · n/N next/previous ≥MED · s cycle floor · S show hidden · t cycle window 5m→15m→1h→24h→boot",
		"tab group by time/category/app · / filter · a mark known · R restart verdict · A ancestry · c live network · e export",
		"", m.cfg.Redactor.String(report.BaselineLine(m.cfg.Baseline)))
	return out
}

func wrap(s string, w int) []string {
	if w < 10 || ansi.StringWidth(s) <= w {
		return []string{s}
	}
	var out []string
	cur := ""
	for _, word := range strings.Fields(s) {
		for ansi.StringWidth(word) > w {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			out = append(out, word[:w])
			word = word[w:]
		}
		switch {
		case cur == "":
			cur = word
		case ansi.StringWidth(cur)+1+ansi.StringWidth(word) <= w:
			cur += " " + word
		default:
			out = append(out, cur)
			cur = word
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func pad(s string, w int) string {
	return s + strings.Repeat(" ", max(0, w-ansi.StringWidth(s)))
}
