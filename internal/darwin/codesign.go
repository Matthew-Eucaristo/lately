package darwin

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

// Signature is what `codesign -dv` says about a program.
type Signature struct {
	Signer    string // event.Signer* class
	TeamID    string
	Authority string // first Authority= line, e.g. "Developer ID Application: Foo Inc (ABCDE12345)"
	Notarized bool   // stapled or online ticket is not checked; "Notarization Ticket=stapled" only
}

var (
	csAuthority = regexp.MustCompile(`(?m)^Authority=(.+)$`)
	csTeam      = regexp.MustCompile(`(?m)^TeamIdentifier=(.+)$`)
	csCache     sync.Map
)

// Sign checks a program's signature, cached per path. Failures to run
// codesign give SignerUnknown, never a guess.
func Sign(ctx context.Context, path string) Signature {
	if path == "" {
		return Signature{}
	}
	if v, ok := csCache.Load(path); ok {
		return v.(Signature)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	// codesign prints details on stderr and exits 1 for unsigned code.
	out, _ := exec.CommandContext(ctx, "/usr/bin/codesign", "-dv", "--verbose=2", path).CombinedOutput()
	sig := ParseCodesign(string(out))
	csCache.Store(path, sig)
	return sig
}

// ParseCodesign classifies `codesign -dv --verbose=2` output.
func ParseCodesign(out string) Signature {
	var s Signature
	if m := csTeam.FindStringSubmatch(out); m != nil && m[1] != "not set" {
		s.TeamID = strings.TrimSpace(m[1])
	}
	if m := csAuthority.FindStringSubmatch(out); m != nil {
		s.Authority = strings.TrimSpace(m[1])
	}
	s.Notarized = strings.Contains(out, "Notarization Ticket=stapled")
	switch {
	case strings.Contains(out, "code object is not signed"):
		s.Signer = event.SignerUnsigned
	case strings.Contains(out, "Signature=adhoc"):
		s.Signer = event.SignerAdhoc
	case strings.HasSuffix(s.Authority, "Software Signing"): // "macOS Software Signing" since macOS 26
		s.Signer = event.SignerApple
	case s.Authority != "" && s.TeamID != "":
		s.Signer = event.SignerDevID
	default:
		s.Signer = event.SignerUnknown // missing file, unreadable, new format
	}
	return s
}

// apply copies a signature onto a subject.
func (s Signature) apply(sub *event.Subject) {
	sub.Signer = s.Signer
	if s.TeamID != "" {
		sub.TeamID = s.TeamID
	}
}
