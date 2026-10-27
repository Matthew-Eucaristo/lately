// Package darwin holds the macOS evidence sources. Every source shells out
// to a tool Apple ships (log, pmset, last, codesign, systemextensionsctl,
// eslogger) or reads a file a normal user can already read; nothing here
// links against Apple frameworks, so the build stays CGO_ENABLED=0.
//
// Parsers take an io.Reader so tests run against redacted fixtures on any
// OS; only the commands themselves need a Mac.
package darwin

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// childNice is the CPU priority of the Apple tools lately starts. A long
// `log show` (a day takes half a minute) then yields to whatever you are
// doing; on an idle Mac it runs just as fast.
const childNice = 10

// lowPriority lowers a started command's CPU priority. Best effort.
func lowPriority(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, childNice)
	}
}

// runCmd runs a command and returns stdout. A var so tests can swap it.
var runCmd = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Start()
	if err == nil {
		lowPriority(cmd)
		err = cmd.Wait()
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			return stdout.Bytes(), fmt.Errorf("%s: %w", name, err)
		}
		return stdout.Bytes(), fmt.Errorf("%s: %s", name, firstLine(msg))
	}
	return stdout.Bytes(), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// localTime is the format /usr/bin/log and most Apple text logs use.
const localTime = "2006-01-02 15:04:05"

func inWindow(t, since, until time.Time) bool {
	return !t.Before(since) && !t.After(until)
}
