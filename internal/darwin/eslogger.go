package darwin

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// ESLogger is the elevated tier: Apple's eslogger (Endpoint Security) run
// as a child process while the user keeps `sudo lately capture` open.
// Events stay in memory; only --save writes them to a file. Apple says the
// output format may change between releases, so unknown shapes become
// "unclassified" events rather than errors or silence.
type ESLogger struct {
	File string    // read a saved capture instead of running eslogger
	Save io.Writer // copy raw lines here while capturing (optional)
}

// ESEvents are the Endpoint Security events lately asks for.
var ESEvents = []string{
	"exec", "fork", "exit",
	"btm_launch_item_add", "btm_launch_item_remove",
	"tcc_modify", "gatekeeper_user_override",
	"xp_malware_detected", "xp_malware_remediated",
	"profile_add", "od_create_user", "authentication", "sudo",
}

const esloggerPath = "/usr/bin/eslogger"

func (s *ESLogger) ID() string        { return "eslogger" }
func (s *ESLogger) Tier() source.Tier { return source.TierElevated }

func (s *ESLogger) Probe(context.Context) source.Capability {
	if s.File != "" {
		return source.Capability{Available: true, Note: "saved capture " + filepath.Base(s.File)}
	}
	if _, err := os.Stat(esloggerPath); err != nil {
		return source.Capability{Needs: []string{"macos 13+"}, Note: "eslogger not found"}
	}
	if os.Geteuid() != 0 {
		return source.Capability{Needs: []string{"root", "fda"}, Note: "run: sudo lately capture (your terminal needs Full Disk Access)"}
	}
	return source.Capability{Available: true}
}

// History reads a saved capture; a live capture has no history.
func (s *ESLogger) History(ctx context.Context, since, until time.Time, emit func(event.Event)) error {
	if s.File == "" {
		return nil
	}
	f, err := os.Open(s.File)
	if err != nil {
		return err
	}
	defer f.Close()
	return ParseES(f, func(e event.Event) {
		if inWindow(e.TS, since, until) {
			emit(e)
		}
	})
}

// Stream runs eslogger until ctx ends. Requested events this macOS does
// not offer are dropped and reported in the returned note.
func (s *ESLogger) Stream(ctx context.Context, emit func(event.Event)) (note string, err error) {
	events := ESEvents
	if out, err := runCmd(ctx, esloggerPath, "--list-events"); err == nil {
		have := map[string]bool{}
		for _, l := range strings.Fields(string(out)) {
			have[l] = true
		}
		var keep, missing []string
		for _, e := range ESEvents {
			if have[e] {
				keep = append(keep, e)
			} else {
				missing = append(missing, e)
			}
		}
		events = keep
		if len(missing) > 0 {
			note = "not offered by this macOS: " + strings.Join(missing, ", ")
		}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, esloggerPath, append(events, "--format", "json")...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return note, err
	}
	if err := cmd.Start(); err != nil {
		return note, err
	}
	var r io.Reader = out
	if s.Save != nil {
		r = io.TeeReader(out, s.Save)
	}
	perr := ParseES(r, emit)
	if perr != nil {
		cancel() // stop eslogger before Wait, or it blocks on a full pipe
		_ = cmd.Wait()
		return note, perr
	}
	werr := cmd.Wait()
	if ctx.Err() != nil {
		return note, nil // the user quit
	}
	msg := strings.TrimSpace(stderr.String())
	if strings.Contains(msg, "NOT_PERMITTED") || strings.Contains(msg, "not permitted") {
		return note, errors.New("eslogger is not permitted: give your terminal Full Disk Access in System Settings › Privacy & Security")
	}
	if werr != nil {
		return note, fmt.Errorf("eslogger: %v %s", werr, firstLine(msg))
	}
	return note, perr
}

// esProcess is the process object eslogger prints.
type esProcess struct {
	AuditToken struct {
		PID  int `json:"pid"`
		EUID int `json:"euid"`
	} `json:"audit_token"`
	PPID        int `json:"ppid"`
	Responsible struct {
		PID int `json:"pid"`
	} `json:"responsible_audit_token"`
	SigningID  string `json:"signing_id"`
	TeamID     string `json:"team_id"`
	IsPlatform bool   `json:"is_platform_binary"`
	Executable struct {
		Path string `json:"path"`
	} `json:"executable"`
	StartTime string `json:"start_time"`
}

func (p *esProcess) subject() event.Subject {
	if p == nil {
		return event.Subject{}
	}
	s := event.Subject{Path: p.Executable.Path, Name: filepath.Base(p.Executable.Path), PID: p.AuditToken.PID,
		PPID: p.PPID, TeamID: p.TeamID, BundleID: p.SigningID}
	switch {
	case p.IsPlatform:
		s.Signer = event.SignerApple
	case p.TeamID != "":
		s.Signer = event.SignerDevID
	}
	if p.Responsible.PID != 0 && p.Responsible.PID != p.AuditToken.PID {
		s.Responsible = strconv.Itoa(p.Responsible.PID)
	}
	return s
}

type esLine struct {
	Time    string                     `json:"time"`
	Process *esProcess                 `json:"process"`
	Event   map[string]json.RawMessage `json:"event"`
}

// ParseES reads eslogger JSON lines.
func ParseES(r io.Reader, emit func(event.Event)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		e, err := ParseESLine(sc.Bytes())
		if err != nil {
			return err
		}
		emit(e)
	}
	return sc.Err()
}

// ParseESLine turns one eslogger line into an event.
func ParseESLine(line []byte) (event.Event, error) {
	var l esLine
	if err := json.Unmarshal(line, &l); err != nil {
		return event.Event{}, fmt.Errorf("eslogger: unreadable line: %w", err)
	}
	ts, _ := time.Parse(time.RFC3339Nano, l.Time)
	e := event.Event{TS: ts, Source: "eslogger", Raw: string(line)}
	e.Subject = l.Process.subject()
	if len(l.Event) != 1 {
		e.Kind = "unclassified"
		return e, nil
	}
	var name string
	var body json.RawMessage
	for k, v := range l.Event {
		name, body = k, v
	}
	e.Set("es_event", name)
	var err error
	switch name {
	case "exec":
		err = esExec(body, &e)
	case "fork":
		var b struct {
			Child *esProcess `json:"child"`
		}
		err = json.Unmarshal(body, &b)
		e.Kind = event.KindExec
		e.Set("op", "fork")
		if b.Child != nil && l.Process != nil {
			e.Subject = b.Child.subject()
			e.Subject.PPID = l.Process.AuditToken.PID
			// the forking process is known too, so the tree can reach it
			e.Set("parent_ppid", strconv.Itoa(l.Process.PPID))
			e.Set("parent_path", l.Process.Executable.Path)
			ps := l.Process.subject()
			e.Set("parent_signer", ps.Signer)
			e.Set("parent_team", ps.TeamID)
		}
	case "exit":
		var b struct {
			Stat int `json:"stat"`
		}
		err = json.Unmarshal(body, &b)
		e.Kind = event.KindExit
		e.Set("status", strconv.Itoa(b.Stat))
	case "btm_launch_item_add", "btm_launch_item_remove":
		err = esBTM(name, body, &e)
	case "tcc_modify":
		err = esTCC(body, &e)
	case "gatekeeper_user_override":
		err = esGatekeeper(body, &e)
	case "xp_malware_detected", "xp_malware_remediated":
		var b map[string]any
		err = json.Unmarshal(body, &b)
		e.Kind = event.KindMalware
		e.Set("threat", "yes")
		e.Set("status", strings.TrimPrefix(name, "xp_malware_"))
		e.Set("malware", str(b["malware_identifier"]))
		if p := str(b["detected_path"]); p != "" {
			e.Subject = event.Subject{Path: p, Name: filepath.Base(p)}
		}
	case "profile_add":
		var b struct {
			Profile struct {
				Identifier  string `json:"identifier"`
				DisplayName string `json:"display_name"`
				Org         string `json:"organization"`
			} `json:"profile"`
		}
		err = json.Unmarshal(body, &b)
		e.Kind = event.KindProfile
		e.Set("profile", b.Profile.DisplayName)
		e.Set("organization", b.Profile.Org)
		e.Subject = event.Subject{Name: b.Profile.DisplayName, BundleID: b.Profile.Identifier}
	case "od_create_user":
		var b map[string]any
		err = json.Unmarshal(body, &b)
		e.Kind = event.KindAccount
		e.Set("account", str(b["user_name"]))
	case "authentication":
		var b map[string]any
		err = json.Unmarshal(body, &b)
		e.Kind = event.KindAuth
		e.Set("method", "authentication")
		e.Set("success", yesNo(b["success"]))
	case "sudo":
		var b map[string]any
		err = json.Unmarshal(body, &b)
		e.Kind = event.KindAuth
		e.Set("method", "sudo")
		e.Set("success", yesNo(b["success"]))
		e.Set("command", str(b["command"]))
	default:
		e.Kind = "unclassified"
	}
	if err != nil {
		e.Kind = "unclassified"
		e.Set("error", "unexpected eslogger shape")
	}
	return e, nil
}

func esExec(body json.RawMessage, e *event.Event) error {
	var b struct {
		Target *esProcess `json:"target"`
		Args   []string   `json:"args"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Kind = event.KindExec
	e.Set("op", "exec")
	if b.Target != nil {
		e.Subject = b.Target.subject()
		e.Set("start", b.Target.StartTime)
	}
	e.Set("args", strings.Join(b.Args, " "))
	if len(b.Args) > 0 {
		e.Set("argv0", filepath.Base(b.Args[0]))
	}
	return nil
}

func esBTM(name string, body json.RawMessage, e *event.Event) error {
	var b struct {
		Instigator *esProcess `json:"instigator"`
		Item       struct {
			Type    int    `json:"item_type"`
			Legacy  bool   `json:"legacy"`
			Managed bool   `json:"managed"`
			URL     string `json:"item_url"`
			AppURL  string `json:"app_url"`
		} `json:"item"`
		Executable string `json:"executable_path"`
	}
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Kind = event.KindPersist
	e.Set("persist", "login_item")
	e.Set("change", map[bool]string{true: "added", false: "removed"}[name == "btm_launch_item_add"])
	e.Set("item_url", b.Item.URL)
	if b.Instigator != nil {
		e.Subject.Responsible = b.Instigator.Executable.Path
	}
	path := b.Executable
	if path == "" {
		path = strings.TrimPrefix(b.Item.URL, "file://")
	}
	e.Subject = event.Subject{Path: path, Name: filepath.Base(path), Responsible: e.Subject.Responsible}
	if b.Item.Managed {
		e.Set("managed", "yes")
	}
	return nil
}

func esTCC(body json.RawMessage, e *event.Event) error {
	var b map[string]any
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Kind = event.KindPermit
	svc := str(b["service"])
	e.Set("service", svc)
	e.Set("service_name", tccName(svc))
	e.Subject = event.Subject{BundleID: str(b["identity"]), Responsible: e.Subject.Path}
	switch str(b["right"]) {
	case "2", "allowed":
		e.Set("decision", "allowed")
	case "0", "denied":
		e.Set("decision", "denied")
	default:
		e.Set("decision", str(b["right"]))
	}
	e.Set("how", "changed (Endpoint Security)")
	if powerfulTCC[svc] {
		e.Set("powerful", "yes")
	}
	return nil
}

func esGatekeeper(body json.RawMessage, e *event.Event) error {
	var b map[string]any
	if err := json.Unmarshal(body, &b); err != nil {
		return err
	}
	e.Kind = event.KindGatekeeper
	e.Set("override", "yes")
	path := ""
	switch f := b["file"].(type) {
	case map[string]any:
		path = str(f["path"])
	case string:
		path = f
	}
	e.Subject = event.Subject{Path: path, Name: filepath.Base(path)}
	return nil
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

func yesNo(v any) string {
	if b, ok := v.(bool); ok && b {
		return "yes"
	}
	return "no"
}
