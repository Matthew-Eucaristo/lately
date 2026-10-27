package collect

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

// Follow runs followers until ctx ends and sends their events in small
// batches (at most every flush interval), so a busy lens cannot flood the
// UI. A follower that stops early sends Done with its error. The channel
// closes, and done is closed, when every follower has returned (so its
// child processes have been waited for).
func Follow(ctx context.Context, fs []source.Follower, flush time.Duration) (updates <-chan Update, done <-chan struct{}) {
	ch := make(chan Update, 64)
	fin := make(chan struct{})
	send := func(u Update) {
		select {
		case ch <- u:
		case <-ctx.Done():
		}
	}
	go func() {
		defer close(ch)
		var wg sync.WaitGroup
		for _, f := range fs {
			wg.Add(1)
			go func(f source.Follower) {
				defer wg.Done()
				var mu sync.Mutex
				var batch []event.Event
				take := func() []event.Event {
					mu.Lock()
					defer mu.Unlock()
					b := batch
					batch = nil
					return b
				}
				ended := make(chan error, 1)
				go func() {
					ended <- f.Follow(ctx, func(e event.Event) {
						mu.Lock()
						batch = append(batch, e)
						mu.Unlock()
					})
				}()
				tick := time.NewTicker(flush)
				defer tick.Stop()
				for {
					select {
					case <-tick.C:
						if b := take(); len(b) > 0 {
							send(Update{Source: f.ID(), Events: b})
						}
					case err := <-ended:
						if ctx.Err() == nil {
							send(Update{Source: f.ID(), Events: take(), Err: err, Done: true})
						}
						return
					}
				}
			}(f)
		}
		wg.Wait()
		close(fin)
	}()
	return ch, fin
}

// Poll follows a source that has no live feed by reading its history
// again every interval. Each read overlaps the last by a margin, because
// a file can be written a little after the time it records; callers drop
// the repeats with Key.
func Poll(s source.Source, every time.Duration) source.Follower {
	return &poller{s: s, every: every}
}

type poller struct {
	s     source.Source
	every time.Duration
}

func (p *poller) ID() string { return p.s.ID() }

func (p *poller) Follow(ctx context.Context, emit func(event.Event)) error {
	last := time.Now()
	t := time.NewTicker(p.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		now := time.Now()
		if err := p.s.History(ctx, last.Add(-2*p.every), now, emit); err != nil && ctx.Err() == nil {
			return err
		}
		last = now
	}
}

// Merge combines update channels into one that closes when all have.
func Merge(ctx context.Context, chs ...<-chan Update) <-chan Update {
	out := make(chan Update, 64)
	var wg sync.WaitGroup
	for _, c := range chs {
		wg.Add(1)
		go func(c <-chan Update) {
			defer wg.Done()
			for u := range c {
				select {
				case out <- u:
				case <-ctx.Done():
					return // the senders stop on ctx too
				}
			}
		}(c)
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// Key identifies an event so overlapping reads (a wider window, a poll,
// a stream that starts while history is still read) keep one copy.
func Key(e event.Event) string {
	return e.Source + "\x00" + e.Kind + "\x00" + strconv.FormatInt(e.TS.UnixNano(), 36) + "\x00" +
		e.Subject.Key() + "\x00" + strconv.Itoa(e.Subject.PID) + "\x00" + e.Raw + "\x00" +
		e.Field("change") + "\x00" + e.Field("plist") + "\x00" + e.Field("file")
}
