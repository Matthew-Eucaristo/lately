package darwin

import (
	"bufio"
	"bytes"
	"context"
	"sort"
	"strconv"
	"strings"
)

// Network history needs a firewall system extension (LuLu, Little
// Snitch) or an Apple-entitled Endpoint Security client. Without one,
// lately can only show what is connected right now.
const NetLimit = "Connection history needs a firewall extension such as LuLu or Little Snitch; lately shows live connections only."

// Conn is one live socket of the user's own processes (lsof cannot see
// other users' sockets without root).
type Conn struct {
	Command string `json:"command"`
	PID     int    `json:"pid"`
	Proto   string `json:"proto"`
	Name    string `json:"name"`  // local->remote
	State   string `json:"state"` // ESTABLISHED, LISTEN, …
}

// Traffic is per-process byte counts since each process started.
type Traffic struct {
	Process  string `json:"process"`
	PID      int    `json:"pid"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// LiveNet takes one snapshot of lsof and nettop.
func LiveNet(ctx context.Context) ([]Conn, []Traffic, error) {
	lo, err := runCmd(ctx, "/usr/sbin/lsof", "-nP", "-i")
	if err != nil && len(lo) == 0 {
		return nil, nil, err
	}
	no, _ := runCmd(ctx, "/usr/bin/nettop", "-P", "-L", "1", "-x")
	return ParseLsof(lo), ParseNettop(no), nil
}

// ParseLsof reads `lsof -nP -i`.
func ParseLsof(out []byte) []Conn {
	var cs []Conn
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		c := Conn{Command: f[0], PID: pid, Proto: f[7], Name: f[8]}
		if len(f) > 9 {
			c.State = strings.Trim(f[9], "()")
		}
		cs = append(cs, c)
	}
	return cs
}

// ParseNettop reads `nettop -P -L 1 -x` CSV, busiest first.
func ParseNettop(out []byte) []Traffic {
	var ts []Traffic
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ",")
		if len(f) < 6 || f[0] == "time" {
			continue
		}
		name := f[1]
		i := strings.LastIndexByte(name, '.')
		if i <= 0 {
			continue
		}
		pid, err := strconv.Atoi(name[i+1:])
		if err != nil {
			continue
		}
		in, _ := strconv.ParseInt(f[4], 10, 64)
		outb, _ := strconv.ParseInt(f[5], 10, 64)
		ts = append(ts, Traffic{Process: name[:i], PID: pid, BytesIn: in, BytesOut: outb})
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].BytesIn+ts[i].BytesOut > ts[j].BytesIn+ts[j].BytesOut })
	return ts
}
