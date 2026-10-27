// Package baseline remembers what lately has already seen on this Mac, so
// it can mark new things as NEW. It stores only salted SHA-256 hashes and
// dates: no names, paths or URLs. One file, removed by `lately forget`.
package baseline

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// FileName is the baseline file inside the app support folder.
const FileName = "baseline.v1.json"

// Status says how far the baseline can be trusted.
type Status int

const (
	Fresh    Status = iota // no file yet: this run builds it and marks nothing NEW
	Loaded                 // normal
	Corrupt                // unreadable: everything counts as first seen, the file is left alone
	Disabled               // --no-baseline: nothing is read or written
)

type file struct {
	Version  int                          `json:"version"`
	Salt     string                       `json:"salt"`
	Created  string                       `json:"created"`
	LastRun  string                       `json:"last_run,omitempty"`
	Seen     map[string]string            `json:"seen"`     // hash(rule, subject) -> first-seen date
	Known    map[string]string            `json:"known"`    // hash(subject) -> date marked known
	Snapshot map[string]map[string]string `json:"snapshot"` // group -> hash(item key) -> short content hash
}

// Baseline is safe for concurrent use.
type Baseline struct {
	mu      sync.Mutex
	path    string
	f       file
	status  Status
	start   Status          // status when opened; FirstSeen answers from it
	loaded  map[string]bool // seen hashes as loaded; saves during a run do not change answers
	warning string
	seenNow map[string]string
	snapNow map[string]map[string]string
}

// DefaultPath is ~/Library/Application Support/lately/baseline.v1.json on
// macOS (os.UserConfigDir elsewhere).
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "lately", FileName), nil
}

// Disable returns a baseline that never reads or writes.
func Disable() *Baseline {
	return &Baseline{status: Disabled, start: Disabled, f: emptyFile(""), seenNow: map[string]string{}}
}

// Open loads the baseline at path. It never fails: problems become a
// status and a warning the UI shows.
func Open(path string) *Baseline {
	b := &Baseline{path: path, seenNow: map[string]string{}, loaded: map[string]bool{}}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		b.status, b.start = Fresh, Fresh
		b.f = emptyFile(newSalt())
		return b
	case err != nil:
		return b.corrupt(fmt.Sprintf("baseline unreadable (%v): everything counts as first seen", err))
	}
	if err := json.Unmarshal(data, &b.f); err != nil || b.f.Version != 1 || len(b.f.Salt) < 32 {
		return b.corrupt("baseline file is damaged or from another version: everything counts as first seen; `lately forget` resets it")
	}
	if b.f.Seen == nil {
		b.f.Seen = map[string]string{}
	}
	if b.f.Known == nil {
		b.f.Known = map[string]string{}
	}
	if b.f.Snapshot == nil {
		b.f.Snapshot = map[string]map[string]string{}
	}
	for h := range b.f.Seen {
		b.loaded[h] = true
	}
	b.status, b.start = Loaded, Loaded
	return b
}

func (b *Baseline) corrupt(msg string) *Baseline {
	b.status, b.start, b.warning = Corrupt, Corrupt, msg
	b.f = emptyFile(newSalt())
	return b
}

func emptyFile(salt string) file {
	return file{Version: 1, Salt: salt, Created: today(),
		Seen: map[string]string{}, Known: map[string]string{}, Snapshot: map[string]map[string]string{}}
}

func newSalt() string {
	s := make([]byte, 16)
	if _, err := rand.Read(s); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(s)
}

func today() string { return time.Now().Format("2006-01-02") }

// Status and Warning describe the baseline for the footer.
func (b *Baseline) Status() Status  { return b.status }
func (b *Baseline) Warning() string { return b.warning }
func (b *Baseline) Path() string    { return b.path }

// LastRun is when lately last saved the baseline.
func (b *Baseline) LastRun() time.Time {
	t, _ := time.Parse(time.RFC3339, b.f.LastRun)
	return t
}

func (b *Baseline) hash(parts ...string) string {
	h := sha256.New()
	h.Write([]byte(b.f.Salt))
	for _, p := range parts {
		h.Write([]byte{0})
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// FirstSeen reports whether (rule, subject) was never seen before this
// run, and records it. Within one run the answer does not change.
func (b *Baseline) FirstSeen(rule, key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	h := b.hash("seen", rule, key)
	if _, ok := b.seenNow[h]; !ok {
		b.seenNow[h] = today()
	}
	switch b.start {
	case Loaded:
		return !b.loaded[h]
	case Corrupt:
		return true
	}
	return false
}

// Known reports whether the subject was acknowledged.
func (b *Baseline) Known(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.f.Known[b.hash("known", key)]
	return ok
}

// MarkKnown acknowledges a subject and saves at once.
func (b *Baseline) MarkKnown(key string) error {
	if b.status == Disabled {
		return errors.New("baseline is off (--no-baseline)")
	}
	if b.status == Corrupt {
		return errors.New("baseline is damaged; run `lately forget` first")
	}
	b.mu.Lock()
	b.f.Known[b.hash("known", key)] = today()
	b.mu.Unlock()
	return b.Save()
}

// Diff compares a snapshot with the last saved one. It returns items that
// appeared or changed since then, and how many disappeared (only a count:
// the baseline holds no names). Groups in failed are neither compared nor
// overwritten. A fresh or damaged baseline has nothing to compare against
// and returns nothing.
func (b *Baseline) Diff(items []source.Item, failed []string) (added, changed []source.Item, removed int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	skip := map[string]bool{}
	for _, g := range failed {
		skip[g] = true
	}
	now := map[string]map[string]string{}
	for g, old := range b.f.Snapshot {
		if skip[g] {
			now[g] = old // keep what we knew
		}
	}
	for _, it := range items {
		if skip[it.Group] {
			continue
		}
		if now[it.Group] == nil {
			now[it.Group] = map[string]string{}
		}
		kh := b.hash("snap", it.Key)
		now[it.Group][kh] = it.Hash
		if b.start != Loaded {
			continue
		}
		old, ok := b.f.Snapshot[it.Group][kh]
		switch {
		case !ok:
			added = append(added, it)
		case old != it.Hash:
			changed = append(changed, it)
		}
	}
	if b.start == Loaded {
		for g, old := range b.f.Snapshot {
			if skip[g] {
				continue
			}
			for kh := range old {
				if _, ok := now[g][kh]; !ok {
					removed++
				}
			}
		}
	}
	b.snapNow = now
	return added, changed, removed
}

// Save merges this run into the file (atomically, mode 0600). Damaged and
// disabled baselines are never written.
func (b *Baseline) Save() error {
	if b.status == Disabled || b.status == Corrupt || b.path == "" {
		return nil
	}
	b.mu.Lock()
	for h, d := range b.seenNow {
		if _, ok := b.f.Seen[h]; !ok {
			b.f.Seen[h] = d
		}
	}
	if b.snapNow != nil {
		b.f.Snapshot = b.snapNow
	}
	b.f.LastRun = time.Now().UTC().Format(time.RFC3339)
	data, err := json.MarshalIndent(b.f, "", " ")
	b.mu.Unlock()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(b.path), 0o700); err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, b.path); err != nil {
		return err
	}
	b.mu.Lock()
	if b.status == Fresh {
		b.status = Loaded
	}
	b.mu.Unlock()
	return nil
}

// Size is the file's size in bytes, or -1.
func (b *Baseline) Size() int64 {
	fi, err := os.Stat(b.path)
	if err != nil {
		return -1
	}
	return fi.Size()
}

// Forget deletes the baseline file and its folder when empty.
func Forget(path string) (bool, error) {
	err := os.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_ = os.Remove(path + ".tmp")
	_ = os.Remove(filepath.Dir(path)) // only succeeds when empty
	return true, nil
}
