package darwin

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"howett.net/plist"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Persistence watches the places software uses to start itself again:
// launch agent and daemon plists, crontab, shell startup files, SSH
// authorized_keys and system extensions. File birth and modification times
// give events inside the window; Snapshot lets the collector also report
// changes made since lately last ran (crontab and extensions have no times).
type Persistence struct{ Home string }

func (p *Persistence) ID() string        { return "persist" }
func (p *Persistence) Tier() source.Tier { return source.TierUser }
func (p *Persistence) Probe(context.Context) source.Capability {
	return source.Capability{Available: true}
}

// launchDirs are the third-party launchd folders; /System ones are sealed.
func (p *Persistence) launchDirs() []struct{ dir, scope string } {
	return []struct{ dir, scope string }{
		{filepath.Join(p.Home, "Library/LaunchAgents"), "user agent"},
		{"/Library/LaunchAgents", "agent for all users"},
		{"/Library/LaunchDaemons", "daemon (runs as root)"},
	}
}

func (p *Persistence) shellFiles() []string {
	var out []string
	for _, f := range []string{".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"} {
		out = append(out, filepath.Join(p.Home, f))
	}
	return out
}

func (p *Persistence) History(ctx context.Context, since, until time.Time, emit func(event.Event)) error {
	var errs []error
	for _, d := range p.launchDirs() {
		ents, err := os.ReadDir(d.dir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
			continue
		}
		for _, ent := range ents {
			if !strings.HasSuffix(ent.Name(), ".plist") {
				continue
			}
			path := filepath.Join(d.dir, ent.Name())
			fi, err := os.Lstat(path)
			if err != nil {
				continue
			}
			change, ts := changed(fi, since, until)
			if change == "" {
				continue
			}
			e := p.launchItem(ctx, path, d.scope)
			e.TS = ts
			e.Set("change", change)
			emit(e)
		}
	}
	for _, f := range p.shellFiles() {
		p.fileChange(f, "shell_rc", since, until, emit)
	}
	p.fileChange(filepath.Join(p.Home, ".ssh/authorized_keys"), "ssh_key", since, until, emit)
	return errors.Join(errs...)
}

// changed reports "added" when a file was born in the window, "changed"
// when only its content time is.
func changed(fi os.FileInfo, since, until time.Time) (string, time.Time) {
	birth, mod := fileTimes(fi)
	switch {
	case !birth.IsZero() && inWindow(birth, since, until):
		return "added", birth
	case inWindow(mod, since, until):
		return "changed", mod
	}
	return "", time.Time{}
}

func (p *Persistence) fileChange(path, kind string, since, until time.Time, emit func(event.Event)) {
	fi, err := os.Lstat(path)
	if err != nil {
		return
	}
	change, ts := changed(fi, since, until)
	if change == "" {
		return
	}
	e := event.Event{TS: ts, Source: "persist", Kind: event.KindPersist}
	e.Subject = event.Subject{Name: filepath.Base(path), Path: path}
	e.Set("persist", kind)
	e.Set("change", change)
	e.Set("file", path)
	emit(e)
}

// LaunchPlist is the part of a launchd plist lately reads.
type LaunchPlist struct {
	Label            string   `plist:"Label"`
	Program          string   `plist:"Program"`
	ProgramArguments []string `plist:"ProgramArguments"`
	RunAtLoad        bool     `plist:"RunAtLoad"`
	KeepAlive        any      `plist:"KeepAlive"`
	StartInterval    int      `plist:"StartInterval"`
}

// ParseLaunchPlist decodes XML or binary launchd plists.
func ParseLaunchPlist(data []byte) (LaunchPlist, error) {
	var lp LaunchPlist
	_, err := plist.Unmarshal(data, &lp)
	return lp, err
}

// ProgramPath is the executable launchd starts.
func (lp LaunchPlist) ProgramPath() string {
	if lp.Program != "" {
		return lp.Program
	}
	if len(lp.ProgramArguments) > 0 {
		return lp.ProgramArguments[0]
	}
	return ""
}

func (p *Persistence) launchItem(ctx context.Context, path, scope string) event.Event {
	e := event.Event{Source: "persist", Kind: event.KindPersist}
	e.Set("plist", path)
	e.Set("scope", scope)
	if strings.Contains(scope, "daemon") {
		e.Set("persist", "launch_daemon")
	} else {
		e.Set("persist", "launch_agent")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		e.Set("error", "unreadable plist")
		e.Subject = event.Subject{Name: filepath.Base(path), Path: path}
		return e
	}
	lp, err := ParseLaunchPlist(data)
	if err != nil {
		e.Set("error", "unparseable plist")
		e.Subject = event.Subject{Name: filepath.Base(path), Path: path}
		return e
	}
	e.Subject = event.Subject{Name: lp.Label, BundleID: lp.Label, Path: lp.ProgramPath()}
	e.Set("label", lp.Label)
	e.Set("program", lp.ProgramPath())
	if len(lp.ProgramArguments) > 1 {
		e.Set("args", strings.Join(lp.ProgramArguments[1:], " "))
	}
	if lp.RunAtLoad {
		e.Set("run_at_load", "yes")
	}
	if lp.KeepAlive != nil && lp.KeepAlive != false {
		e.Set("keep_alive", "yes")
	}
	sig := Sign(ctx, lp.ProgramPath())
	sig.apply(&e.Subject)
	e.Set("authority", sig.Authority)
	if sig.Signer == event.SignerUnsigned || sig.Signer == event.SignerAdhoc {
		e.Set("weak_signature", "yes")
	}
	return e
}

// Snapshot lists every watched item with a content hash, by group.
func (p *Persistence) Snapshot(ctx context.Context) ([]source.Item, []string) {
	var items []source.Item
	var failed []string
	for _, d := range p.launchDirs() {
		ents, err := os.ReadDir(d.dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			failed = append(failed, "launchd")
			continue
		}
		for _, ent := range ents {
			if !strings.HasSuffix(ent.Name(), ".plist") {
				continue
			}
			path := filepath.Join(d.dir, ent.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				data = []byte("unreadable") // still an item: never "removed" by accident
			}
			persist := "launch_agent"
			if strings.Contains(d.scope, "daemon") {
				persist = "launch_daemon"
			}
			items = append(items, source.Item{Group: "launchd", Key: "plist:" + path, Hash: hash(data), Kind: event.KindPersist,
				Subject: event.Subject{Name: ent.Name(), Path: path},
				Fields:  map[string]string{"persist": persist, "plist": path, "scope": d.scope}})
		}
	}
	for _, f := range append(p.shellFiles(), filepath.Join(p.Home, ".ssh/authorized_keys")) {
		data, err := os.ReadFile(f)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			failed = append(failed, "files")
			continue
		}
		kind := "shell_rc"
		if strings.HasSuffix(f, "authorized_keys") {
			kind = "ssh_key"
		}
		items = append(items, source.Item{Group: "files", Key: "file:" + f, Hash: hash(data), Kind: event.KindPersist,
			Subject: event.Subject{Name: filepath.Base(f), Path: f},
			Fields:  map[string]string{"persist": kind, "file": f}})
	}
	out, err := runCmd(ctx, "/usr/bin/crontab", "-l")
	switch {
	case err == nil:
		items = append(items, CrontabItems(out)...)
	case strings.Contains(err.Error(), "no crontab for"):
		// an empty crontab is a valid, empty group
	default:
		failed = append(failed, "cron")
	}
	if out, err := runCmd(ctx, "/usr/bin/systemextensionsctl", "list"); err == nil {
		items = append(items, SysextItems(out)...)
	} else {
		failed = append(failed, "sysext")
	}
	return items, failed
}

// CrontabItems turns crontab -l output into one item per active entry.
func CrontabItems(out []byte) []source.Item {
	var items []source.Item
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || isEnvLine(line) {
			continue
		}
		items = append(items, source.Item{Group: "cron", Key: "cron:" + line, Hash: hash([]byte(line)), Kind: event.KindPersist,
			Subject: event.Subject{Name: "crontab entry"},
			Fields:  map[string]string{"persist": "cron", "entry": line}})
	}
	return items
}

func isEnvLine(l string) bool {
	i := strings.IndexByte(l, '=')
	return i > 0 && !strings.ContainsAny(l[:i], " \t*")
}

// SysextItems parses `systemextensionsctl list`. Rows are tab-separated:
// enabled, active, teamID, bundleID (version), name, [state]. Lines that
// match neither a row nor a known header still become items, so an
// unknown format shows up as a change instead of being ignored.
func SysextItems(out []byte) []source.Item {
	var items []source.Item
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "", strings.HasSuffix(line, "extension(s)"), strings.HasPrefix(line, "---"),
			strings.HasPrefix(line, "enabled\tactive"), strings.HasPrefix(line, "enabled active"):
			continue
		}
		cols := strings.Split(line, "\t")
		sub := event.Subject{Name: line}
		fields := map[string]string{"entry": line}
		if len(cols) >= 5 {
			bundle := strings.Fields(cols[3])
			sub = event.Subject{Name: strings.TrimSpace(cols[4]), TeamID: strings.TrimSpace(cols[2])}
			if len(bundle) > 0 {
				sub.BundleID = bundle[0]
			}
			if len(cols) >= 6 {
				fields["state"] = strings.Trim(strings.TrimSpace(cols[5]), "[]")
			}
		}
		key := "sysext:" + sub.BundleID
		if sub.BundleID == "" {
			key = "sysext:" + line
		}
		items = append(items, source.Item{Group: "sysext", Key: key, Hash: hash([]byte(line)), Kind: event.KindSysext, Subject: sub, Fields: fields})
	}
	return items
}

func hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}
