package restart

import (
	"testing"
	"time"
)

func TestDecide(t *testing.T) {
	boot := time.Date(2026, 10, 27, 2, 41, 15, 0, time.Local)
	shut := boot.Add(-time.Minute)
	base := Evidence{Boot: boot, PrevBoot: boot.Add(-11 * time.Hour), AppleSilicon: true, WtmpKnown: true, BreadcrumbKnown: true}
	with := func(f func(*Evidence)) Evidence { e := base; f(&e); return e }
	cases := []struct {
		name string
		ev   Evidence
		want string
	}{
		{"clean", with(func(e *Evidence) { e.ShutdownBefore = &shut }), Clean},
		{"update", with(func(e *Evidence) { e.ShutdownBefore = &shut; e.Updates = []string{"macOS 27.0.1"} }), Update},
		{"panic beats everything", with(func(e *Evidence) { e.ShutdownBefore = &shut; e.BreadcrumbPanic = "/x.panic" }), Panic},
		{"hung shutdown", with(func(e *Evidence) { e.StallReports = []string{"shutdown_stall.shutdownStall"}; e.Watchdog = true }), Stall},
		{"watchdog alone", with(func(e *Evidence) { e.Watchdog = true }), Unknown},
		{"nothing at all", base, Unknown},
	}
	for _, c := range cases {
		v := Decide(c.ev)
		if v.Kind != c.want {
			t.Errorf("%s: %s, want %s", c.name, v.Kind, c.want)
		}
		if len(v.Checks) < 5 || v.Title == "" || v.Explain == "" {
			t.Errorf("%s: incomplete verdict %+v", c.name, v)
		}
	}
	if v := Decide(with(func(e *Evidence) { e.Charge = "80"; e.PowerSource = "AC" })); v.Explain == Decide(base).Explain {
		t.Error("a battery-backed Mac should not blame power loss first")
	}
	if v := Decide(base); len(v.Notes) == 0 || !v.Approx {
		t.Error("Apple silicon verdicts must say they are inferred")
	}
}

func TestCleanForSharing(t *testing.T) {
	ev := Evidence{Boot: time.Date(2026, 10, 27, 2, 41, 0, 0, time.FixedZone("X", 7*3600)), StallReports: []string{"secret-host.stall"}, LastWordsProcess: "secret"}
	c := ev.Clean(func(s string) string { return "R" })
	if c.Boot.Location() != time.UTC || c.StallReports[0] != "R" || c.LastWordsProcess != "R" || ev.StallReports[0] != "secret-host.stall" {
		t.Errorf("clean: %+v (original %+v)", c, ev)
	}
}
