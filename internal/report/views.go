package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
	"github.com/Matthew-Eucaristo/lately/internal/redact"
	"github.com/Matthew-Eucaristo/lately/internal/restart"
)

// RestartLines renders the "why did my Mac restart?" view.
func RestartLines(v restart.Verdict, ev restart.Evidence) []string {
	chip := "Intel"
	if ev.AppleSilicon {
		chip = "Apple silicon"
	}
	out := []string{
		fmt.Sprintf("Why did my Mac restart?   booted %s (%s)", when(ev.Boot), chip),
		fmt.Sprintf("VERDICT  %s %s", v.Level.Glyph(), v.Title),
		"  " + v.Explain,
		strings.Repeat("─", 78),
	}
	for _, c := range v.Checks {
		mark := "·"
		if c.Found {
			mark = "✓"
		}
		line := fmt.Sprintf("  %s %-11s %s", mark, c.Name, c.Text)
		if c.Note != "" {
			line += "   → " + c.Note
		}
		out = append(out, line)
	}
	out = append(out, strings.Repeat("─", 78))
	for _, n := range v.Notes {
		out = append(out, "  "+n)
	}
	if v.Approx {
		out = append(out, "  Confidence: ≈ inferred.")
	}
	return out
}

func when(t time.Time) string {
	t = t.Local()
	if y, m, d := time.Now().Date(); t.Year() == y && t.Month() == m && t.Day() == d {
		return t.Format("15:04") + " today"
	}
	return t.Format("Mon Jan 2 15:04")
}

// AncestryLines renders a process chain, root first, marking where
// knowledge ends.
func AncestryLines(t *ancestry.Tree, pid int, r *redact.Redactor) []string {
	c := t.Chain(pid)
	if len(c.Nodes) == 0 {
		return []string{fmt.Sprintf("Ancestry · pid %d is not in the %s.", pid, t.Source),
			"Exited processes are only known while `sudo lately capture` runs."}
	}
	self := c.Nodes[len(c.Nodes)-1]
	head := fmt.Sprintf("Ancestry · %s (pid %d)", self.Name(), self.PID)
	if l, ok := self.Lived(); ok {
		head += fmt.Sprintf(" · lived %.2f s · %s → %s", l.Seconds(), self.Start.Local().Format("15:04:05.000"), self.End.Local().Format("15:04:05.000"))
	}
	out := []string{head}
	indent := ""
	if c.Broken {
		out = append(out, fmt.Sprintf("┄ chain broken: parent pid %d was not seen (it exited before capture started)", c.Gap))
	}
	for i, n := range c.Nodes {
		prefix := indent + "└─ "
		if i == 0 && !c.Broken {
			prefix = ""
		}
		line := prefix + n.Name()
		if n.PID == 1 {
			line = prefix + "launchd"
		}
		line += fmt.Sprintf(" (%d)", n.PID)
		if n.Args != "" {
			line += "  " + shorten(n.Args, 70)
		}
		if w := signerShort(n.Signer, n.TeamID); w != "" {
			line += "   " + w
		}
		if i == len(c.Nodes)-1 {
			line += "   ◀"
		}
		out = append(out, r.String(line))
		if i > 0 || c.Broken {
			indent += "   "
		}
	}
	src := "Source: " + t.Source
	if !t.Since.IsZero() {
		src += " since " + t.Since.Local().Format("15:04:05") + " · events before it are unknown"
	}
	return append(out, src)
}

func signerShort(signer, team string) string {
	switch signer {
	case "apple":
		return "Apple"
	case "devid":
		return "Dev ID " + team
	case "adhoc":
		return "ad-hoc"
	case "unsigned":
		return "unsigned"
	}
	return ""
}

func shorten(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}
