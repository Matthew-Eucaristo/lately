package collect

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Matthew-Eucaristo/lately/internal/event"
	"github.com/Matthew-Eucaristo/lately/internal/source"
)

type liveFake struct {
	id  string
	n   int
	err error
}

func (f *liveFake) ID() string { return f.id }
func (f *liveFake) Follow(ctx context.Context, emit func(event.Event)) error {
	for i := range f.n {
		emit(event.Event{TS: time.Unix(int64(i), 0), Kind: "launch"})
	}
	if f.err != nil {
		return f.err
	}
	<-ctx.Done()
	return nil
}

func TestFollowBatchesAndReportsEnds(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	boom := errors.New("log stream: exit status 64")
	ch, done := Follow(ctx, []source.Follower{&liveFake{id: "ok", n: 500}, &liveFake{id: "bad", n: 3, err: boom}}, 20*time.Millisecond)
	got := map[string]int{}
	var badErr error
	for u := range ch {
		got[u.Source] += len(u.Events)
		if u.Source == "bad" && u.Done {
			badErr = u.Err
		}
		if got["ok"] == 500 && badErr != nil {
			cancel()
		}
	}
	<-done
	if got["ok"] != 500 || got["bad"] != 3 || !errors.Is(badErr, boom) {
		t.Errorf("got %v, bad err %v", got, badErr)
	}
}

type histFake struct {
	mu    sync.Mutex
	spans [][2]time.Time
}

func (h *histFake) ID() string        { return "reports" }
func (h *histFake) Tier() source.Tier { return source.TierUser }
func (h *histFake) Probe(context.Context) source.Capability {
	return source.Capability{Available: true}
}
func (h *histFake) History(_ context.Context, since, until time.Time, emit func(event.Event)) error {
	h.mu.Lock()
	h.spans = append(h.spans, [2]time.Time{since, until})
	h.mu.Unlock()
	emit(event.Event{TS: until, Kind: "crash"})
	return nil
}

func TestPollOverlapsReads(t *testing.T) {
	h := &histFake{}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	_ = Poll(h, 20*time.Millisecond).Follow(ctx, func(event.Event) {})
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.spans) < 2 {
		t.Fatalf("polled %d times", len(h.spans))
	}
	for i := 1; i < len(h.spans); i++ {
		if !h.spans[i][0].Before(h.spans[i-1][1]) {
			t.Errorf("read %d does not overlap the previous one: %v", i, h.spans)
		}
	}
}

func TestMergeAndKey(t *testing.T) {
	a, b := make(chan Update, 1), make(chan Update, 1)
	a <- Update{Source: "a"}
	b <- Update{Source: "b"}
	close(a)
	close(b)
	n := 0
	for range Merge(context.Background(), a, b) {
		n++
	}
	if n != 2 {
		t.Errorf("merged %d updates", n)
	}
	e := event.Event{TS: time.Unix(5, 0), Source: "reports", Kind: "crash", Subject: event.Subject{Name: "Foo"}, Raw: "x"}
	f := e
	f.Fields = map[string]string{"file": "Foo-2.ips"}
	if Key(e) != Key(e) || Key(e) == Key(f) {
		t.Error("Key must be stable and tell different files apart")
	}
}
