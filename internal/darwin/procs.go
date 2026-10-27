package darwin

import (
	"bufio"
	"bytes"
	"context"
	"strconv"
	"strings"

	"github.com/Matthew-Eucaristo/lately/internal/ancestry"
)

// LiveTree is the current process table from ps: enough to explain a
// process that is still running, never one that already exited.
func LiveTree(ctx context.Context) (*ancestry.Tree, error) {
	out, err := runCmd(ctx, "/bin/ps", "-axo", "pid=,ppid=,comm=")
	if err != nil {
		return nil, err
	}
	return ParsePS(out), nil
}

// ParsePS reads `ps -axo pid=,ppid=,comm=` output.
func ParsePS(out []byte) *ancestry.Tree {
	t := ancestry.New("live process table")
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 {
			continue
		}
		pid, err1 := strconv.Atoi(f[0])
		ppid, err2 := strconv.Atoi(f[1])
		if err1 != nil || err2 != nil {
			continue
		}
		t.Put(ancestry.Node{PID: pid, PPID: ppid, Path: strings.Join(f[2:], " ")})
	}
	return t
}
