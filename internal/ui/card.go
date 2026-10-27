package ui

import (
	"fmt"
	"math"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/relate"
	"github.com/Matthew-Eucaristo/lately/internal/report"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
)

// perReason caps how many links of one reason a card lists.
const perReason = 8

// cardPos is one card on the stack, with its selected related row (kept
// as a ref, because follow can insert rows above it) and scroll offset.
type cardPos struct {
	f   ref
	sel *ref
	off int
}

// openCard shows f's card. push keeps the current card underneath, so esc
// walks back along the relations that were followed.
func (m *Model) openCard(f *rules.Finding, push bool) {
	if !push {
		m.cardStack = nil
	} else if n := len(m.cardStack); n > 0 {
		m.cardStack[n-1].off = m.cardOff
	}
	m.cardStack = append(m.cardStack, cardPos{f: refOf(f)})
	m.view, m.showRaw, m.cardSel, m.cardOff = cardView, false, 0, 0
}

// cardFinding is the finding on top of the stack. Findings are rebuilt on
// every reclassify, so it is looked up by ID.
func (m *Model) cardFinding() *rules.Finding {
	if len(m.cardStack) == 0 {
		return nil
	}
	top := &m.cardStack[len(m.cardStack)-1]
	f := top.f.find(m.findings)
	if f != nil {
		top.f = refOf(f) // follow the group as it changes
	}
	return f
}

// related is cached per finding and reclassify.
func (m *Model) related(f *rules.Finding) []relate.Link {
	if f == nil {
		return nil
	}
	// "around then" depends on what is shown, so the floor and S are in the key.
	if key := fmt.Sprint(f.ID, m.ver, m.meta.Floor, m.meta.All); key != m.relKey {
		m.rel = relate.Find(m.findings, f, func(o *rules.Finding) bool { return report.Shown(o, m.meta) })
		m.relKey = key
	}
	return m.rel
}

// links are the related rows a card lists (perReason of each) and, per
// reason, how many were left out.
func (m *Model) links(f *rules.Finding) ([]relate.Link, map[string]int) {
	var out []relate.Link
	more, n := map[string]int{}, map[string]int{}
	for _, l := range m.related(f) {
		if n[l.Reason]++; n[l.Reason] > perReason {
			more[l.Reason]++
			continue
		}
		out = append(out, l)
	}
	return out, more
}

// selectLink moves the related selection and remembers which finding it is.
func (m *Model) selectLink(ls []relate.Link, i int) {
	if len(ls) == 0 || len(m.cardStack) == 0 {
		return
	}
	m.cardSel = max(0, min(len(ls)-1, i))
	r := refOf(ls[m.cardSel].F)
	m.cardStack[len(m.cardStack)-1].sel = &r
}

func (m *Model) cardKey(k string) tea.Cmd {
	f := m.cardFinding()
	ls, _ := m.links(f)
	switch k {
	case "esc", "backspace", "left", "h":
		m.cardStack = m.cardStack[:max(0, len(m.cardStack)-1)]
		if len(m.cardStack) == 0 {
			m.view = timelineView
			return nil
		}
		m.cardSel, m.cardOff, m.showRaw = 0, m.cardStack[len(m.cardStack)-1].off, false
	case "up", "k":
		if len(ls) == 0 {
			m.cardOff = max(0, m.cardOff-1)
		} else {
			m.selectLink(ls, m.cardSel-1)
		}
	case "down", "j":
		if len(ls) == 0 {
			m.cardOff++
		} else {
			m.selectLink(ls, m.cardSel+1)
		}
	case "pgup":
		m.cardOff = max(0, m.cardOff-m.height/2)
	case "pgdown":
		m.cardOff += m.height / 2
	case "enter", "right", "l":
		if m.cardSel < len(ls) {
			m.openCard(ls[m.cardSel].F, true)
		}
	case "r":
		m.showRaw = !m.showRaw
	case "f":
		return m.toggleFollow()
	case "a":
		return m.acknowledge(f)
	case "A":
		return m.openAncestry(f)
	case "R":
		return m.open(restartView, m.restartLines)
	case "e":
		m.openExport()
	}
	return nil
}

// cardLines draws the card: the fixed sections, the subject's activity
// over the window, and the related findings, scrolled so the selected
// relation stays on screen.
func (m *Model) cardLines() []string {
	f := m.cardFinding()
	if f == nil {
		return []string{"", "  This event is no longer in the window (it was narrowed or reloaded).", "", faint.Render("  esc back")}
	}
	red := m.cfg.Redactor
	w := max(50, min(m.width, 120))
	inner := w - 4
	// Open layout, as in fell: horizontal rules only, so wide glyphs and
	// terminals that draw box lines thinly cannot break a frame.
	row := func(label, text string) string {
		return "  " + heading.Render(fmt.Sprintf("%-8s", label)) + " " + ansi.Truncate(text, inner-9, "…")
	}
	rule := func(title string) string {
		t := "── " + title + " "
		return faint.Render(t + strings.Repeat("─", max(0, w-ansi.StringWidth(t))))
	}

	top := fmt.Sprintf("%s %s · %s · %s ", f.Level.Glyph(), f.Level.Short(), f.Rule.Category, red.String(f.Title))
	stamp := " " + f.Event.TS.Local().Format("Jan 2 15:04:05")
	if d := len(m.cardStack); d > 1 {
		stamp = fmt.Sprintf(" card %d · esc back%s", d, stamp)
	}
	top = ansi.Truncate(top, w-ansi.StringWidth(stamp)-3, "…")
	top = " " + top + strings.Repeat("─", max(0, w-1-ansi.StringWidth(top)-ansi.StringWidth(stamp))) + stamp

	var body []string
	for _, s := range report.Card(f, red) {
		if s.Label == "RAW" && !m.showRaw && len(s.Lines) > 2 {
			s.Lines = append(s.Lines[:2:2], faint.Render("(r: show full raw record)"))
		}
		for i, l := range s.Lines {
			for j, wl := range wrap(l, inner-10) {
				label := ""
				if i == 0 && j == 0 {
					label = s.Label
				}
				body = append(body, row(label, wl))
			}
		}
	}

	// Activity: every occurrence of this subject in the window.
	body = append(body, rule("ACTIVITY"))
	pts, n := m.subjectPoints(f)
	sw := inner - 10 - 12
	body = append(body, row("", faint.Render(clockLabel(m.meta.Since, m.meta.Until)+" ")+
		strip(pts, m.meta.Since, m.meta.Until, sw, f.Event.TS)+faint.Render(" "+m.untilLabel())))
	who := red.String(f.Event.Subject.Label())
	at := ansi.StringWidth(clockLabel(m.meta.Since, m.meta.Until)) + 1 + bucket(f.Event.TS, m.meta.Since, m.meta.Until, sw)
	note := fmt.Sprintf("this · %d event(s) of %s in the window", n, who)
	caret := pad("", at) + green.Render("▲") + faint.Render(" "+note)
	if at+2+ansi.StringWidth(note) > inner-9 {
		caret = pad(faint.Render(note+" "), at) + green.Render("▲")
		if ansi.StringWidth(note)+1 > at {
			caret = pad("", at) + green.Render("▲")
		}
	}
	body = append(body, row("", caret))

	// Related findings.
	ls, more := m.links(f)
	if sel := m.cardStack[len(m.cardStack)-1].sel; sel != nil { // keep the same row selected
		if o := sel.find(m.findings); o != nil {
			for i, l := range ls {
				if l.F == o {
					m.cardSel = i
				}
			}
		}
	}
	m.cardSel = max(0, min(m.cardSel, len(ls)-1))
	selLine := -1
	if len(ls) == 0 {
		body = append(body, rule("RELATED"))
		for _, l := range wrap("Nothing else in the window shares its process, app, developer or install, and nothing shown happened within 2 minutes.", inner-10) {
			body = append(body, row("", faint.Render(l)))
		}
	} else {
		body = append(body, rule(fmt.Sprintf("RELATED · %s · ↑↓ select ⏎ open", strings.Join(relate.Counts(m.related(f)), " · "))))
		last := ""
		for i, l := range ls {
			if l.Reason != last && last != "" && more[last] > 0 {
				body = append(body, row("", faint.Render(fmt.Sprintf("  +%d more %s", more[last], last))))
			}
			last = l.Reason
			if i == m.cardSel {
				selLine = len(body)
			}
			body = append(body, m.linkRow(l, i == m.cardSel, w))
		}
		if more[last] > 0 {
			body = append(body, row("", faint.Render(fmt.Sprintf("  +%d more %s", more[last], last))))
		}
	}

	keys := " ↑↓ related · ⏎ open · r raw · a known · A ancestry · f follow · esc back"
	if len(m.cardStack) > 1 {
		keys = " ↑↓ related · ⏎ open · esc previous card · r raw · a known · A ancestry"
	}
	bottom := strings.Repeat("─", max(0, w-ansi.StringWidth(keys))) + keys

	// Scroll the body between the pinned top and bottom lines.
	h := max(3, m.height-2)
	if m.status != "" {
		h--
	}
	if selLine >= 0 {
		if selLine < m.cardOff {
			m.cardOff = selLine
		}
		if selLine >= m.cardOff+h {
			m.cardOff = selLine - h + 1
		}
	}
	m.cardOff = max(0, min(m.cardOff, max(0, len(body)-h)))
	out := []string{levelStyle(f.Level).Bold(true).Render(top)}
	out = append(out, body[m.cardOff:min(len(body), m.cardOff+h)]...)
	if m.cardOff+h < len(body) {
		out[len(out)-1] = row("", faint.Render(fmt.Sprintf("… %d more lines (↓ or pgdn)", len(body)-m.cardOff-h)))
	}
	out = append(out, faint.Render(bottom))
	if m.status != "" {
		out = append(out, " "+green.Render(m.status))
	}
	return out
}

// linkRow is one related finding: offset from this event, reason, level,
// category and title; hidden rows say why they are hidden.
func (m *Model) linkRow(l relate.Link, sel bool, w int) string {
	o := l.F
	cur := "   "
	if sel {
		cur = " " + cursorC + " "
	}
	lvl := levelStyle(o.Level).Render(fmt.Sprintf("%s %-4s", o.Level.Glyph(), o.Level.Short()))
	head := fmt.Sprintf("%s%7s  %-14s %s  %-8s ", cur, delta(l.Delta), l.Reason, lvl, o.Rule.Category)
	tail := ""
	if h := o.Hidden(m.meta.Floor); h != "" {
		tail = faint.Render(" (hidden: " + h + ")")
	}
	title := m.cfg.Redactor.String(o.Title)
	room := w - ansi.StringWidth(head) - ansi.StringWidth(tail) - 1
	title = ansi.Truncate(title, max(8, room), "…")
	if sel {
		title = bold.Render(title)
	}
	return head + title + tail
}

// subjectPoints are the times of every finding about f's subject.
func (m *Model) subjectPoints(f *rules.Finding) ([]point, int) {
	key := f.Event.Subject.Key()
	var pts []point
	for _, o := range m.findings {
		if o == f || key != "" && o.Event.Subject.Key() == key {
			for _, t := range o.Times {
				pts = append(pts, point{t, o.Level})
			}
		}
	}
	return pts, len(pts)
}

// delta is a compact signed offset: -2m10s, +4s, +3h05m, -2d.
func delta(d time.Duration) string {
	sign := "+"
	if d < 0 {
		sign, d = "-", -d
	}
	d = d.Round(time.Second)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%s%ds", sign, int(d.Seconds()))
	case d < 10*time.Minute:
		return fmt.Sprintf("%s%dm%02ds", sign, int(d.Minutes()), int(d.Seconds())%60)
	case d < time.Hour:
		return fmt.Sprintf("%s%dm", sign, int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%s%dh%02dm", sign, int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%s%dd", sign, int(d.Hours()/24))
}

type point struct {
	t time.Time
	l event.Level
}

var blocks = []rune("▁▂▃▄▅▆▇█")

// bucket is the cell of t in a w-cell strip over [from, to].
func bucket(t, from, to time.Time, w int) int {
	span := to.Sub(from)
	if span <= 0 || w <= 0 {
		return 0
	}
	return max(0, min(w-1, int(float64(t.Sub(from))/float64(span)*float64(w))))
}

// strip is a w-cell histogram of pts over [from, to]: the height is the
// count (log scale), the colour the highest level in the cell. The cell
// holding mark is drawn reversed.
func strip(pts []point, from, to time.Time, w int, mark time.Time) string {
	if w < 4 {
		return ""
	}
	count := make([]int, w)
	lvl := make([]event.Level, w)
	top := 0
	for _, p := range pts {
		if p.t.Before(from) || p.t.After(to) {
			continue
		}
		i := bucket(p.t, from, to, w)
		count[i]++
		lvl[i] = max(lvl[i], p.l)
		top = max(top, count[i])
	}
	mi := -1
	if !mark.IsZero() && !mark.Before(from) && !mark.After(to) {
		mi = bucket(mark, from, to, w)
	}
	var b, run strings.Builder
	runKey := -1
	var runStyle lipgloss.Style
	for i := range w {
		key, st, ch := -1, faint, "·"
		if count[i] > 0 {
			h := int(math.Ceil(math.Log1p(float64(count[i])) / math.Log1p(float64(top)) * float64(len(blocks))))
			key, st, ch = int(lvl[i]), levelStyle(lvl[i]), string(blocks[max(1, min(len(blocks), h))-1])
		}
		if i == mi { // the cursor's cell, in the cursor's colour
			key, st, ch = 99, green.Bold(true), "█"
			if count[i] == 0 {
				ch = "│"
			}
		}
		if key != runKey && run.Len() > 0 {
			b.WriteString(runStyle.Render(run.String()))
			run.Reset()
		}
		runKey, runStyle = key, st
		run.WriteString(ch)
	}
	b.WriteString(runStyle.Render(run.String()))
	return b.String()
}

// clockLabel formats the start of a span: the time, with the date when the
// span is longer than a day.
func clockLabel(from, to time.Time) string {
	if to.Sub(from) > 24*time.Hour {
		return from.Local().Format("Jan 2 15:04")
	}
	return from.Local().Format("15:04")
}

func (m *Model) untilLabel() string {
	if m.follow {
		return "now"
	}
	return m.meta.Until.Local().Format("15:04")
}
