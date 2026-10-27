package darwin

import (
	"context"
	"os"
	"os/user"
	"regexp"
	"strings"

	"github.com/Matthew-Eucaristo/lately/internal/redact"
)

var serialRe = regexp.MustCompile(`"IOPlatformSerialNumber" = "([^"]+)"`)

// Identity collects the personal details the redactor must hide. Missing
// pieces are simply not redacted by name (paths still are, by pattern).
func Identity(ctx context.Context, home string) redact.Identity {
	id := redact.Identity{Home: home}
	u, err := user.Current()
	if su := os.Getenv("SUDO_USER"); os.Geteuid() == 0 && su != "" {
		u, err = user.Lookup(su) // under sudo the person is SUDO_USER, not root
	}
	if err == nil {
		id.User = u.Username
		id.FullName = u.Name
	}
	if h, err := os.Hostname(); err == nil {
		id.Hosts = append(id.Hosts, h, strings.TrimSuffix(h, ".local"))
	}
	for _, k := range []string{"ComputerName", "LocalHostName", "HostName"} {
		if out, err := runCmd(ctx, "/usr/sbin/scutil", "--get", k); err == nil {
			if s := strings.TrimSpace(string(out)); s != "" {
				id.Hosts = append(id.Hosts, s)
			}
		}
	}
	if out, err := runCmd(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"); err == nil {
		if m := serialRe.FindSubmatch(out); m != nil {
			id.Serial = string(m[1])
		}
	}
	return id
}
