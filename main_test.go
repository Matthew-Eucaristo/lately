package main

import (
	"context"
	"testing"
	"time"
)

func TestParseWindow(t *testing.T) {
	ctx := context.Background()
	for in, want := range map[string]time.Duration{"5m": 5 * time.Minute, "1h": time.Hour, "2d": 48 * time.Hour} {
		label, since, err := parseWindow(ctx, in)
		if err != nil || label != in {
			t.Fatalf("%s: %v", in, err)
		}
		if d := time.Since(since); d < want || d > want+time.Minute {
			t.Errorf("%s: since %v ago", in, d)
		}
	}
	for _, bad := range []string{"", "soon", "-5m", "0s"} {
		if _, _, err := parseWindow(ctx, bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"--min-level", "loud", "--list"}, {"--since", "soon", "--list"}, {"--bogus"}, {"extra-arg"}} {
		err := run(args)
		ee, ok := err.(*exitError)
		if !ok || ee.code != 4 {
			t.Errorf("%v: got %v, want exit 4", args, err)
		}
	}
}
