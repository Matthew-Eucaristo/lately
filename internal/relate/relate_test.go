package relate

import (
	"testing"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/rules"
)

func finding(id string, ts time.Time, kind string, s event.Subject, fields map[string]string) *rules.Finding {
	return &rules.Finding{ID: id, Event: event.Event{TS: ts, Kind: kind, Subject: s, Fields: fields}, Rule: &rules.Rule{ID: id}}
}

func TestFind(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	app := event.Subject{Name: "MeetApp", BundleID: "com.meetapp", Path: "/Applications/MeetApp.app/Contents/MacOS/MeetApp", PID: 400, PPID: 1, TeamID: "TEAM1", Signer: event.SignerDevID}
	self := finding("self", t0, event.KindLaunch, app, nil)
	all := []*rules.Finding{
		self,
		finding("proc", t0.Add(time.Minute), event.KindCrash, event.Subject{Name: "MeetApp", PID: 400}, nil),
		finding("child", t0.Add(2*time.Second), event.KindLaunch, event.Subject{Name: "helper", PID: 401, PPID: 400}, nil),
		finding("behalf", t0.Add(5*time.Second), event.KindPermit, event.Subject{BundleID: "com.meetapp.camera", Responsible: "com.meetapp"}, nil),
		finding("agent", t0.Add(-time.Hour), event.KindPersist, event.Subject{Name: "com.meetapp.agent"}, map[string]string{"program": app.Path}),
		finding("install", t0.Add(-2*time.Hour), event.KindInstall, event.Subject{Name: "MeetApp", BundleID: "com.meetapp"}, nil),
		finding("again", t0.Add(-3*time.Hour), event.KindLaunch, event.Subject{BundleID: "com.meetapp", PID: 77}, nil),
		finding("dev", t0.Add(-4*time.Hour), event.KindLaunch, event.Subject{Name: "Other", BundleID: "com.meetapp.other", TeamID: "TEAM1"}, nil),
		finding("near", t0.Add(90*time.Second), event.KindCrash, event.Subject{Name: "Unrelated"}, nil),
		finding("far", t0.Add(time.Hour), event.KindCrash, event.Subject{Name: "Unrelated2"}, nil),
		finding("reused", t0.Add(13*time.Hour), event.KindLaunch, event.Subject{Name: "zsh", PID: 400}, nil),
	}
	got := map[string]string{}
	var order []string
	for _, l := range Find(all, self, func(*rules.Finding) bool { return true }) {
		got[l.F.ID] = l.Reason
		order = append(order, l.F.ID)
	}
	want := map[string]string{"proc": SameProcess, "child": Child, "behalf": OnBehalf, "agent": Program,
		"install": Install, "again": SameApp, "dev": SameDev, "near": Nearby}
	for id, r := range want {
		if got[id] != r {
			t.Errorf("%s: reason %q, want %q", id, got[id], r)
		}
	}
	for _, id := range []string{"self", "far", "reused"} {
		if _, ok := got[id]; ok {
			t.Errorf("%s should not be related", id)
		}
	}
	if order[0] != "proc" || order[len(order)-1] != "near" {
		t.Errorf("order: %v", order)
	}

	// The other direction: the camera prompt names MeetApp as responsible.
	cam := all[3]
	if ls := Find(all, cam, nil); len(ls) == 0 || ls[0].F.ID != "self" || ls[0].Reason != ActedFor {
		t.Errorf("camera prompt should lead to the app it acted for: %+v", ls)
	}
	if c := Counts(Find(all, self, nil)); len(c) == 0 || c[0] != "1 same process" {
		t.Errorf("counts: %v", c)
	}
}

func TestParentAndPersistDuringInstall(t *testing.T) {
	t0 := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	kid := finding("kid", t0, event.KindExec, event.Subject{Name: "sh", PID: 9, PPID: 8}, nil)
	dad := finding("dad", t0.Add(-time.Second), event.KindExec, event.Subject{Name: "osascript", PID: 8}, nil)
	in := finding("in", t0.Add(-time.Minute), event.KindInstall, event.Subject{Name: "Foo VPN"}, nil)
	daemon := finding("daemon", t0, event.KindPersist, event.Subject{Name: "com.foo.helper"}, nil)
	if ls := Find([]*rules.Finding{kid, dad}, kid, nil); len(ls) != 1 || ls[0].Reason != Parent {
		t.Errorf("parent: %+v", ls)
	}
	if ls := Find([]*rules.Finding{in, daemon}, daemon, nil); len(ls) != 1 || ls[0].Reason != Install {
		t.Errorf("install: %+v", ls)
	}
	if Find(nil, nil, nil) != nil {
		t.Error("nil finding")
	}
}
