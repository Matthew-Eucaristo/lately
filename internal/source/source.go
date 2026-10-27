// Package source defines the small interface every platform's evidence
// sources implement. macOS lives in internal/darwin; Linux (journald,
// coredumpctl) and Windows (event log, Reliability Monitor) can be added
// as further packages without touching rules or views.
package source

import (
	"context"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
)

// Tier says what a source needs to run.
type Tier string

const (
	TierUser     Tier = "user"     // no prompts, no root
	TierElevated Tier = "elevated" // sudo (and Full Disk Access) while the user runs it
)

// Capability is a source's probe result.
type Capability struct {
	Available bool     `json:"available"`
	Needs     []string `json:"needs,omitempty"` // "root", "fda", "macos"
	Note      string   `json:"note,omitempty"`
}

// Source reads history for a time window and emits normalized events.
type Source interface {
	ID() string
	Tier() Tier
	Probe(ctx context.Context) Capability
	History(ctx context.Context, since, until time.Time, emit func(event.Event)) error
}

// Item is one entry of a snapshot (a launch agent, a crontab, an
// extension). Hash changes when the item's content changes.
type Item struct {
	Group   string // "launchd", "files", "cron", "sysext": compared as a whole
	Key     string // stable identity, e.g. the plist path
	Hash    string // content fingerprint
	Kind    string
	Subject event.Subject
	Fields  map[string]string
}

// Snapshotter is an optional interface for sources whose evidence is a
// current state; the collector diffs snapshots against the baseline to find
// items that appeared or changed since lately last ran. failed names groups
// that could not be read: their previous snapshot is kept and not compared,
// so a failing command never turns into "everything was added" next time.
type Snapshotter interface {
	Snapshot(ctx context.Context) (items []Item, failed []string)
}

// Streamer is an optional interface for live sources (the elevated
// eslogger capture). It runs until ctx ends; note reports anything the
// source had to leave out.
type Streamer interface {
	Stream(ctx context.Context, emit func(event.Event)) (note string, err error)
}
