// Package event holds the normalized event every source emits and the
// severity levels rules assign to it.
package event

import (
	"fmt"
	"strings"
	"time"
)

// Level is a Sigma-style severity.
type Level int

const (
	Info Level = iota
	Low
	Medium
	High
	Critical
)

var levelNames = [...]string{"info", "low", "medium", "high", "critical"}

func (l Level) String() string { return levelNames[l.clamp()] }

// Short is the fixed-width label used in timeline rows.
func (l Level) Short() string { return [...]string{"INFO", "LOW", "MED", "HIGH", "CRIT"}[l.clamp()] }

// Glyph is shown next to the label so meaning never depends on colour.
func (l Level) Glyph() string { return [...]string{"·", "○", "●", "▲", "✖"}[l.clamp()] }

func (l Level) clamp() Level { return max(Info, min(Critical, l)) }

// ParseLevel accepts full names and the short labels (med, crit).
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "low":
		return Low, nil
	case "medium", "med":
		return Medium, nil
	case "high":
		return High, nil
	case "critical", "crit":
		return Critical, nil
	}
	return Info, fmt.Errorf("unknown level %q (want info, low, medium, high or critical)", s)
}

// Signer classes, from the code signature when it was checked.
const (
	SignerApple    = "apple"    // Software Signing / platform binary
	SignerDevID    = "devid"    // Developer ID or App Store, has a Team ID
	SignerAdhoc    = "adhoc"    // ad-hoc signature, no identity
	SignerUnsigned = "unsigned" // no signature
	SignerUnknown  = ""         // not checked or could not be read
)

// Subject is who an event is about.
type Subject struct {
	Name        string `json:"name,omitempty"`
	Path        string `json:"path,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
	TeamID      string `json:"team_id,omitempty"`
	Signer      string `json:"signer,omitempty"`
	PID         int    `json:"pid,omitempty"`
	PPID        int    `json:"ppid,omitempty"`
	Responsible string `json:"responsible,omitempty"`
}

// Key identifies the subject for baselines and grouping: the most stable
// identifier available.
func (s Subject) Key() string {
	switch {
	case s.BundleID != "":
		return "bundle:" + s.BundleID
	case s.Path != "":
		return "path:" + s.Path
	case s.Name != "":
		return "name:" + s.Name
	}
	return ""
}

// Label is a short human name for the subject.
func (s Subject) Label() string {
	switch {
	case s.Name != "":
		return s.Name
	case s.BundleID != "":
		return s.BundleID
	case s.Path != "":
		return s.Path[strings.LastIndex(s.Path, "/")+1:]
	}
	return "unknown"
}

// IsApple reports whether the subject is part of macOS. A bundle ID alone
// is not proof, so it only counts when no signature says otherwise.
func (s Subject) IsApple() bool {
	if s.Signer != SignerUnknown {
		return s.Signer == SignerApple
	}
	if strings.HasPrefix(s.BundleID, "com.apple.") {
		return true
	}
	for _, p := range []string{"/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"} {
		if strings.HasPrefix(s.Path, p) {
			return true
		}
	}
	return false
}

// Kinds of events. Rules match on these.
const (
	KindLaunch     = "launch"
	KindExec       = "exec"
	KindExit       = "exit"
	KindCrash      = "crash"
	KindInstall    = "install"
	KindPersist    = "persist"
	KindPermit     = "permit"
	KindGatekeeper = "gatekeeper"
	KindMalware    = "malware"
	KindPower      = "power"
	KindBoot       = "boot"
	KindPanic      = "panic"
	KindAuth       = "auth"
	KindAccount    = "account"
	KindProfile    = "profile"
	KindSysext     = "sysext"
	KindLog        = "log"
	KindKernel     = "kernel"
)

// Event is one normalized record. Fields hold source-specific values that
// rules match on; Raw keeps the original line because Apple's formats drift.
type Event struct {
	TS         time.Time         `json:"ts"`
	Source     string            `json:"source"`
	Kind       string            `json:"kind"`
	Subject    Subject           `json:"subject"`
	Fields     map[string]string `json:"fields,omitempty"`
	Raw        string            `json:"raw,omitempty"`
	Approx     bool              `json:"approximate,omitempty"` // inferred from fragile evidence
	Redactions int               `json:"macos_redactions,omitempty"`
}

// Field returns a field or "".
func (e Event) Field(k string) string { return e.Fields[k] }

// Set stores a field, creating the map on first use.
func (e *Event) Set(k, v string) {
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	e.Fields[k] = v
}
