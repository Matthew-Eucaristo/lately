package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Matthew-Eucaristo/lately/internal/source"
)

func TestLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lately", FileName)
	b := Open(path)
	if b.Status() != Fresh {
		t.Fatal("missing file should be fresh")
	}
	if b.FirstSeen("r", "bundle:com.example.secret") {
		t.Error("a fresh baseline marks nothing new")
	}
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	if b.FirstSeen("r", "bundle:com.example.later") {
		t.Error("a first run stays a first run after saving")
	}
	b.Diff([]source.Item{{Group: "launchd", Key: "plist:/Users/someone/Library/LaunchAgents/a.plist", Hash: "1"}}, nil)
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	for _, leak := range []string{"secret", "someone", "LaunchAgents", "com.example"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("baseline file contains %q", leak)
		}
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}

	b = Open(path)
	if b.Status() != Loaded || b.LastRun().IsZero() {
		t.Fatalf("status %v", b.Status())
	}
	if b.FirstSeen("r", "bundle:com.example.secret") {
		t.Error("seen subject reported as new")
	}
	if !b.FirstSeen("r", "bundle:com.example.other") {
		t.Error("unseen subject should be new")
	}
	added, changed, removed := b.Diff([]source.Item{{Group: "launchd", Key: "plist:/x/b.plist", Hash: "2"}}, nil)
	if len(added) != 1 || len(changed) != 0 || removed != 1 {
		t.Errorf("diff: +%d ~%d -%d", len(added), len(changed), removed)
	}
	if err := b.MarkKnown("bundle:com.example.other"); err != nil {
		t.Fatal(err)
	}
	if !b.FirstSeen("r", "bundle:com.example.other") {
		t.Error("saving mid-run (marking known) must not change first-seen answers")
	}
	if !Open(path).Known("bundle:com.example.other") {
		t.Error("known mark not saved")
	}

	if ok, err := Forget(path); !ok || err != nil {
		t.Fatalf("forget: %v %v", ok, err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Error("empty folder left behind")
	}
}

func TestCorruptFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	b := Open(path)
	if b.Status() != Corrupt || b.Warning() == "" {
		t.Fatal("corrupt file not detected")
	}
	if !b.FirstSeen("r", "anything") {
		t.Error("a damaged baseline must treat everything as first seen")
	}
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(path); string(data) != "{not json" {
		t.Error("a damaged baseline must never be overwritten")
	}
	if b.MarkKnown("x") == nil {
		t.Error("marking known on a damaged baseline must fail")
	}
}

func TestDisabledWritesNothing(t *testing.T) {
	b := Disable()
	if b.FirstSeen("r", "k") || b.Save() != nil || b.MarkKnown("k") == nil {
		t.Error("disabled baseline should be inert")
	}
}
