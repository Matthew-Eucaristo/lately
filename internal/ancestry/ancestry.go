// Package ancestry rebuilds process trees from exec, fork and exit events
// (elevated capture) or from a live process table. Like witr, it never
// guesses a missing parent: the chain is marked broken instead.
package ancestry

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

// Node is one process.
type Node struct {
	PID, PPID   int
	Path        string
	Args        string
	Signer      string
	TeamID      string
	Responsible string
	Start, End  time.Time
}

// Name is the executable's base name.
func (n Node) Name() string {
	if i := strings.LastIndexByte(n.Path, '/'); i >= 0 {
		return n.Path[i+1:]
	}
	return n.Path
}

// Lived is how long the process ran, if both ends were seen.
func (n Node) Lived() (time.Duration, bool) {
	if n.Start.IsZero() || n.End.IsZero() {
		return 0, false
	}
	return n.End.Sub(n.Start), true
}

// Tree indexes processes by PID. PIDs are reused, so the newest process
// with a PID wins; capture windows are short enough for this to hold.
type Tree struct {
	nodes  map[int]*Node
	Since  time.Time // first event seen; nothing before it is known
	Source string    // "capture" or "live process table"
}

// New returns an empty tree.
func New(source string) *Tree { return &Tree{nodes: map[int]*Node{}, Source: source} }

// Add folds one event into the tree. Non-process events are ignored.
func (t *Tree) Add(e event.Event) {
	if e.Kind != event.KindExec && e.Kind != event.KindExit {
		return
	}
	if t.Since.IsZero() || e.TS.Before(t.Since) {
		t.Since = e.TS
	}
	pid := e.Subject.PID
	if pid == 0 {
		return
	}
	if pp := e.Subject.PPID; pp != 0 && t.nodes[pp] == nil && e.Field("parent_path") != "" {
		ppp, _ := strconv.Atoi(e.Field("parent_ppid"))
		t.nodes[pp] = &Node{PID: pp, PPID: ppp, Path: e.Field("parent_path"), Signer: e.Field("parent_signer"), TeamID: e.Field("parent_team")}
	}
	n := t.nodes[pid]
	switch {
	case e.Kind == event.KindExit:
		if n != nil {
			n.End = e.TS
		}
		return
	case n == nil || e.Field("op") == "fork" && !n.End.IsZero():
		n = &Node{PID: pid, Start: e.TS}
		t.nodes[pid] = n
	}
	if e.Subject.PPID != 0 {
		n.PPID = e.Subject.PPID
	}
	if e.Subject.Path != "" {
		n.Path = e.Subject.Path
	}
	if a := e.Field("args"); a != "" {
		n.Args = a
	}
	n.Signer, n.TeamID, n.Responsible = e.Subject.Signer, e.Subject.TeamID, e.Subject.Responsible
}

// Put adds a node directly (live process tables).
func (t *Tree) Put(n Node) { t.nodes[n.PID] = &n }

// Get returns a process.
func (t *Tree) Get(pid int) (Node, bool) {
	n, ok := t.nodes[pid]
	if !ok {
		return Node{}, false
	}
	return *n, true
}

// Chain is a process and its ancestors, root first. Broken is true when an
// ancestor was not in the tree (it exited before capture started, or the
// process was handed over by launchd or LaunchServices).
type Chain struct {
	Nodes  []Node
	Broken bool
	Gap    int // PID of the first unknown parent when Broken
}

// Chain walks up from pid to launchd.
func (t *Tree) Chain(pid int) Chain {
	var c Chain
	seen := map[int]bool{}
	for pid > 0 && !seen[pid] {
		seen[pid] = true
		n, ok := t.nodes[pid]
		if !ok && pid == 1 {
			c.Nodes = append(c.Nodes, Node{PID: 1, Path: "/sbin/launchd", Signer: "apple"})
			break
		}
		if !ok {
			c.Broken, c.Gap = true, pid
			break
		}
		c.Nodes = append(c.Nodes, *n)
		if pid == 1 {
			break
		}
		pid = n.PPID
	}
	for i, j := 0, len(c.Nodes)-1; i < j; i, j = i+1, j-1 {
		c.Nodes[i], c.Nodes[j] = c.Nodes[j], c.Nodes[i]
	}
	return c
}

// ShortLived returns processes that started and exited within d, newest
// first: the "window that flashed" candidates.
func (t *Tree) ShortLived(d time.Duration) []Node {
	var out []Node
	for _, n := range t.nodes {
		if l, ok := n.Lived(); ok && l <= d {
			out = append(out, *n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.After(out[j].Start) })
	return out
}

// Len is the number of known processes.
func (t *Tree) Len() int { return len(t.nodes) }
