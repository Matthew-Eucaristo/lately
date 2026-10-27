package rules

import (
	"strings"
	"testing"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

type fakeCtx struct {
	first map[string]bool // subject keys never seen
	known map[string]bool
}

func (c fakeCtx) FirstSeen(_, key string) bool { return c.first[key] }
func (c fakeCtx) Known(key string) bool        { return c.known[key] }

func ev(kind string, fields map[string]string, sub event.Subject) event.Event {
	return event.Event{TS: time.Date(2026, 10, 27, 14, 0, 0, 0, time.UTC), Kind: kind, Fields: fields, Subject: sub, Source: "test"}
}

func TestBuiltinRulesLoad(t *testing.T) {
	s := Builtin()
	if len(s.Rules) < 25 {
		t.Fatalf("only %d rules", len(s.Rules))
	}
	for _, r := range s.Rules {
		if r.What == "" || r.Matters == "" || r.Do == "" || r.Category == "" || r.Title == "" {
			t.Errorf("rule %s lacks card text", r.ID)
		}
		if r.Category != strings.ToUpper(r.Category) {
			t.Errorf("rule %s: category must be an uppercase word", r.ID)
		}
	}
}

func TestParseRejectsBadRules(t *testing.T) {
	for _, bad := range []string{
		"- {id: a, level: loud, tier: user, title: x}\n- {id: z, level: low, tier: user, title: x, match: {}}",
		"- {id: a, level: low, tier: user, title: x, match: {kind: crash}}",
		"- {id: a, level: low, tier: root, title: x, match: {}}",
		"- {id: a, level: low, tier: user, title: x}\n- {id: a, level: low, tier: user, title: x}",
		"- {id: a, level: low, tier: user, title: x, match: {not: {k: [v]}}}",
		"- {id: a, level: low, tier: user, title: x, first_seen: only}",
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestClassify(t *testing.T) {
	s := Builtin()
	agent := event.Subject{Name: "com.example.agent", BundleID: "com.example.agent", Path: "/x/agent", Signer: event.SignerUnsigned}
	cases := []struct {
		name  string
		e     event.Event
		ctx   fakeCtx
		rule  string
		level event.Level
	}{
		{"unsigned daemon is critical", ev("persist", map[string]string{"persist": "launch_daemon", "change": "added", "weak_signature": "yes"}, agent), fakeCtx{}, "persist.launch_daemon_unsigned", event.Critical},
		{"signed new daemon stays high", ev("persist", map[string]string{"persist": "launch_daemon"}, event.Subject{Name: "d", Signer: event.SignerDevID}), fakeCtx{first: map[string]bool{"name:d": true}}, "persist.launch_daemon", event.High},
		{"apple agent drops to medium", ev("persist", map[string]string{"persist": "launch_agent"}, event.Subject{Name: "a", Signer: event.SignerApple}), fakeCtx{}, "persist.launch_agent", event.Medium},
		{"crash never critical", ev("crash", map[string]string{"report_kind": "crash"}, event.Subject{Name: "Foo", Signer: event.SignerUnsigned}), fakeCtx{first: map[string]bool{"name:Foo": true}}, "crash.app", event.High},
		{"apple crash stays medium", ev("crash", map[string]string{"report_kind": "crash"}, event.Subject{Name: "Safari", BundleID: "com.apple.Safari", Signer: event.SignerApple}), fakeCtx{}, "crash.app", event.Medium},
		{"first-seen powerful grant is high", ev("permit", map[string]string{"powerful": "yes", "decision": "allowed"}, event.Subject{BundleID: "com.example.foo"}), fakeCtx{first: map[string]bool{"bundle:com.example.foo": true}}, "permit.grant", event.High},
		{"known powerful grant is low", ev("permit", map[string]string{"powerful": "yes", "decision": "allowed"}, event.Subject{BundleID: "com.example.foo"}), fakeCtx{}, "permit.grant", event.Low},
		{"first launch only when new", ev("launch", map[string]string{"identity": "app"}, event.Subject{BundleID: "com.example.new"}), fakeCtx{first: map[string]bool{"bundle:com.example.new": true}}, "launch.first_run", event.Low},
		{"seen launch is info", ev("launch", map[string]string{"identity": "app"}, event.Subject{BundleID: "com.example.old"}), fakeCtx{}, "launch.app", event.Info},
		{"xprotect detection", ev("malware", map[string]string{"threat": "yes", "status": "ThreatDetected"}, event.Subject{Signer: event.SignerApple}), fakeCtx{}, "malware.xprotect", event.Critical},
		{"unknown kind still shows", ev("brand-new", nil, event.Subject{}), fakeCtx{}, "unclassified", event.Low},
		{"watchdog", ev("panic", map[string]string{"evidence": "watchdog"}, event.Subject{Signer: event.SignerApple}), fakeCtx{}, "restart.watchdog", event.Medium},
		{"marked known demotes", ev("persist", map[string]string{"persist": "cron"}, event.Subject{Name: "crontab entry"}), fakeCtx{known: map[string]bool{"name:crontab entry": true}}, "persist.cron", event.High},
	}
	for _, c := range cases {
		fs := s.Classify([]event.Event{c.e}, c.ctx)
		if len(fs) != 1 {
			t.Errorf("%s: %d findings", c.name, len(fs))
			continue
		}
		if fs[0].Rule.ID != c.rule || fs[0].Level != c.level {
			t.Errorf("%s: got %s/%s, want %s/%s (%v)", c.name, fs[0].Rule.ID, fs[0].Level, c.rule, c.level, fs[0].Adjust)
		}
	}
}

func TestHiddenRules(t *testing.T) {
	s := Builtin()
	f := s.Classify([]event.Event{ev("crash", map[string]string{"report_kind": "fault"}, event.Subject{Name: "x", BundleID: "com.apple.x"})}, nil)[0]
	if f.Hidden(event.Info) != "apple" {
		t.Errorf("Apple rows below medium are hidden, got %q", f.Hidden(event.Info))
	}
	p := s.Classify([]event.Event{ev("panic", map[string]string{"evidence": "panic"}, event.Subject{Signer: event.SignerApple})}, nil)[0]
	if p.Hidden(event.Medium) != "" {
		t.Error("a panic is Apple's kernel but must never be hidden")
	}
}

func TestBurstAndGroup(t *testing.T) {
	s := Builtin()
	var evs []event.Event
	for i := range 3 {
		e := ev("crash", map[string]string{"report_kind": "crash"}, event.Subject{Name: "Foo"})
		e.TS = e.TS.Add(time.Duration(i) * 15 * time.Minute)
		evs = append(evs, e)
	}
	other := ev("crash", map[string]string{"report_kind": "crash"}, event.Subject{Name: "Bar"})
	fs := s.Process(append(evs, other), nil)
	if len(fs) != 2 {
		t.Fatalf("want 2 rows, got %d", len(fs))
	}
	var foo *Finding
	for _, f := range fs {
		if f.Event.Subject.Name == "Foo" {
			foo = f
		}
	}
	if foo.Count != 3 || foo.Level != event.High || !strings.HasSuffix(foo.Title, "×3") {
		t.Errorf("burst: count %d level %s title %q", foo.Count, foo.Level, foo.Title)
	}
}

func TestCorrelateInstall(t *testing.T) {
	s := Builtin()
	in := ev("install", map[string]string{"by": "Installer", "version": "3.2"}, event.Subject{Name: "Foo"})
	pe := ev("persist", map[string]string{"persist": "launch_agent"}, event.Subject{Name: "com.foo.updater"})
	pe.TS = in.TS.Add(time.Second)
	far := ev("persist", map[string]string{"persist": "launch_agent"}, event.Subject{Name: "com.bar"})
	far.TS = in.TS.Add(time.Hour)
	fs := s.Process([]event.Event{in, pe, far}, nil)
	for _, f := range fs {
		switch f.Event.Subject.Name {
		case "com.foo.updater":
			if len(f.Why) == 0 || !strings.Contains(f.Why[0], "Foo install") {
				t.Errorf("why = %v", f.Why)
			}
		case "com.bar":
			if len(f.Why) != 0 {
				t.Errorf("unrelated install linked: %v", f.Why)
			}
		}
	}
}

func TestExpand(t *testing.T) {
	e := ev("permit", map[string]string{"service_name": "Camera"}, event.Subject{BundleID: "com.example.foo", PID: 42})
	if got := Expand("{name} asked for {service_name} ({missing}) pid {pid}", e); got != "com.example.foo asked for Camera pid 42" {
		t.Errorf("got %q", got)
	}
}

func TestBurstNeedsItsWindow(t *testing.T) {
	s := Builtin()
	var evs []event.Event
	for i := range 3 { // 3 failures, but 4.5 minutes apart: not within 5m
		e := ev("auth", map[string]string{"success": "no", "method": "sudo"}, event.Subject{Name: "sudo"})
		e.TS = e.TS.Add(time.Duration(i) * 270 * time.Second)
		evs = append(evs, e)
	}
	fs := s.Process(evs, nil)
	if len(fs) != 1 || fs[0].Count != 3 || fs[0].Level != event.Low {
		t.Fatalf("spread-out failures must not burst: %+v", fs[0])
	}
}
